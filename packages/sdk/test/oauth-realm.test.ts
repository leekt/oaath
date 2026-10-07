/**
 * OAuth-approved Grants through a simulated browser and portal: the realm's
 * session key is the grant signer, the account root signs the replayable
 * install with the SDK's own offline preparation, and only a returned request
 * that is exactly the application's own is stored and applied.
 */
import { IDBFactory } from "fake-indexeddb";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createOAAth } from "../src/index.js";
import { ECDSA_VALIDATOR } from "../src/kernel/deployment/v33.js";
import { ecdsaKey } from "../src/kernel/key/ecdsa.js";
import { prepareDerivedAccountPermissionApproval } from "../src/kernel.js";
import { createChainFixture, permissionInput } from "./support/browser.js";

const ISSUER = "https://issuer.example";
const ORIGIN = "https://app.example";
const REDIRECT = `${ORIGIN}/callback`;
const CLIENT = "0123456789abcdef0123456789abcdef01234567";
const ACCOUNT = "0x62b5f314710bc515d87276a9d00527ac482b2e6a";
const RESPONSE = "oaath.authorization-response/v1";

type Behaviour =
  | "approve"
  | "cancel"
  | Readonly<{ tamper: (request: Record<string, unknown>) => void }>;

/** An issuer, a portal, and a browser window, all in memory. */
async function browser(behaviour: Behaviour = "approve") {
  const root = privateKeyToAccount(generatePrivateKey());
  const rootKey = ecdsaKey({
    account: { address: root.address, sign: ({ hash }) => root.sign({ hash }) },
    validator: ECDSA_VALIDATOR,
  });
  const ownerCredential = {
    version: "oaath.owner-credential-profile/v1",
    kind: "ecdsa",
    address: root.address.toLowerCase(),
  };
  const accountProfile = {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "kernel_factory",
    entryPoint: { version: "0.9" },
    ownerCredential,
  };
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256" }] };
  const pars = new Map<string, URLSearchParams>();
  let token: Record<string, unknown> | null = null;
  const popups: { closed: boolean }[] = [];

  async function authorize(href: string, popup: object) {
    const url = new URL(href);
    const parId = url.searchParams.get("request_uri")!.split(":").pop()!;
    const par = pars.get(parId)!;
    const reply = (query: Record<string, string>) => {
      const event = new Event("message");
      Object.defineProperties(event, {
        data: {
          value: { type: RESPONSE, url: `${REDIRECT}?${new URLSearchParams(query)}` },
        },
        origin: { value: ORIGIN },
        source: { value: popup },
      });
      window.dispatchEvent(event);
    };
    if (behaviour === "cancel") {
      reply({ error: "access_denied", state: par.get("state")!, iss: ISSUER });
      return;
    }
    const [detail] = JSON.parse(par.get("authorization_details")!);
    const requestedAt = Math.floor(Date.now() / 1000);
    // The relay's compose.
    const request: Record<string, unknown> = {
      version: "oaath.permission-request/v2",
      requestId: parId,
      context: {
        version: "oaath.workspace-account-context/v1",
        workspaceId: ACCOUNT,
        workspaceKind: "personal",
        accountId: ACCOUNT,
      },
      application: {
        applicationId: CLIENT,
        clientId: CLIENT,
        origin: ORIGIN,
        deviceId: detail.device_id,
      },
      chainScope: "all",
      logicalAccount: accountProfile,
      operatorCredential: detail.signer,
      policy: detail.policy,
      requestedAt,
      expiresAt: detail.expires_at,
      sessionSigner: null,
    };
    if (typeof behaviour === "object") behaviour.tamper(request);
    const decision = await prepareDerivedAccountPermissionApproval({
      request: request as never,
      chainId: 31337,
      account: ACCOUNT,
    }).sign(rootKey, requestedAt);
    const { installApproval, ...rest } = decision;
    const idToken = await new SignJWT({
      nonce: par.get("nonce"),
      verified: false,
      oaath_account: accountProfile,
      signer: { id: "root-signer", kind: "ecdsa", profile: ownerCredential },
    })
      .setProtectedHeader({ alg: "ES256", kid: "k1" })
      .setIssuer(ISSUER)
      .setAudience(CLIENT)
      .setSubject(ACCOUNT)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(privateKey);
    token = {
      id_token: idToken,
      access_token: "access",
      token_type: "Bearer",
      expires_in: 600,
      scope: "openid",
      authorization_details: [
        {
          type: "oaath_grant",
          grant_id: parId,
          permission_request: request,
          decision: rest,
          enable: installApproval,
        },
      ],
    };
    reply({ code: "code-1", state: par.get("state")!, iss: ISSUER });
  }

  const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    const json = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    if (url.pathname === "/oauth/jwks") return json(jwks);
    const form = new URLSearchParams(String(init?.body ?? ""));
    if (url.pathname === "/oauth/par") {
      const id = `par-${pars.size + 1}`;
      pars.set(id, form);
      return json({ request_uri: `urn:ietf:params:oauth:request_uri:${id}`, expires_in: 300 }, 201);
    }
    if (url.pathname === "/oauth/token") return json(token);
    return json({ error: "not_found" }, 404);
  });

  const window = Object.assign(new EventTarget(), {
    open: vi.fn(() => {
      const popup = {
        closed: false,
        close() {
          popup.closed = true;
        },
        location: {
          set href(value: string) {
            // The portal answers later, as a real window does.
            if (value.startsWith(`${ISSUER}/authorize`))
              setTimeout(() => void authorize(value, popup), 0);
          },
        },
      };
      popups.push(popup);
      return popup;
    }),
  });
  vi.stubGlobal("window", window);
  vi.stubGlobal("location", { origin: ORIGIN, href: `${ORIGIN}/` });
  vi.stubGlobal("fetch", fetch);
  const chain = createChainFixture({ chainId: 31337 });
  const input = {
    chains: [chain.capability],
    approvals: { kind: "oauth" as const, issuer: ISSUER, clientId: CLIENT, redirectUri: REDIRECT },
    origin: ORIGIN,
  };
  return { input, window, popups, pars, chain, root };
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
