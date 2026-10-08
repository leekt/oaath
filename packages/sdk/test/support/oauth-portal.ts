/**
 * An OAAth issuer, its portal, and the dapp's browser window, all in memory.
 * The portal composes the permission request the way the relay does and the
 * account root signs it with the SDK's offline
 * prepareDerivedAccountPermissionApproval, as the portal SPA does.
 */
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { vi } from "vitest";
import { ECDSA_VALIDATOR } from "../../src/kernel/deployment/v33.js";
import { ecdsaKey } from "../../src/kernel/key/ecdsa.js";
import type { KeyProfile } from "../../src/kernel/types.js";
import { prepareDerivedAccountPermissionApproval } from "../../src/kernel.js";

export const ISSUER = "https://issuer.example";
export const ORIGIN = "https://app.example";
export const REDIRECT = `${ORIGIN}/callback`;
export const CLIENT = "0123456789abcdef0123456789abcdef01234567";
const RESPONSE = "oaath.authorization-response/v1";

export type PortalBehaviour =
  | "approve"
  | "cancel"
  /** A member's request: the token waits for `decide` on the root's behalf. */
  | "pending"
  | Readonly<{ tamper: (request: Record<string, unknown>) => void }>;

export interface OAuthPortalOptions {
  readonly behaviour?: PortalBehaviour;
  readonly chainId?: number;
  /** The root's factory-derived account; any address when nothing is executed. */
  readonly account?: `0x${string}`;
  readonly root?: Readonly<{ credential: object; key: Readonly<KeyProfile> }>;
  /** The root's signed owner operation for a PAR's `oaath_operation` request. */
  readonly signOperation?: (request: unknown) => Promise<unknown>;
  /** The issuer's answer to an off-chain invalidation; `"down"` never answers. */
  readonly invalidation?: number | "down";
  /** The id_token `oaath_accounts` claim; defaults to the account, as root. */
  readonly accounts?: unknown;
}

function ecdsaRoot() {
  const root = privateKeyToAccount(generatePrivateKey());
  return {
    credential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: root.address.toLowerCase(),
    },
    key: ecdsaKey({
      account: { address: root.address, sign: ({ hash }) => root.sign({ hash }) },
      validator: ECDSA_VALIDATOR,
    }),
  };
}

/** Stubs window, location and fetch; the caller restores them with vi.unstubAllGlobals. */
export async function installOAuthPortal(options: OAuthPortalOptions = {}) {
  const behaviour = options.behaviour ?? "approve";
  const chainId = options.chainId ?? 31_337;
  const account = options.account ?? "0x62b5f314710bc515d87276a9d00527ac482b2e6a";
  const root = options.root ?? ecdsaRoot();
  const accountProfile = {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "kernel_factory",
    entryPoint: { version: "0.9" },
    ownerCredential: root.credential,
  };
  const accounts = Object.hasOwn(options, "accounts")
    ? options.accounts
    : [{ address: account, role: "root", status: "active" }];
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256" }] };
  const pars = new Map<string, URLSearchParams>();
  let token: Record<string, unknown> | null = null;
  const popups: { closed: boolean }[] = [];
  // The root's decision on a pending request; the code redeems once.
  let rootDecision: "approve" | "reject" | null = null;
  let redeemed = false;
  const tokenCalls = { count: 0 };
  const invalidations: { grantId: string; body: Record<string, unknown> }[] = [];

  /** The portal's decision for one authorization URL, as its redirect query. */
  async function authorize(href: string): Promise<Record<string, string>> {
    const url = new URL(href);
    const parId = url.searchParams.get("request_uri")!.split(":").pop()!;
    const par = pars.get(parId)!;
    if (behaviour === "cancel")
      return { error: "access_denied", state: par.get("state")!, iss: ISSUER };
    const signIn = (nonce: string | null) =>
      new SignJWT({
        nonce,
        verified: true,
        oaath_account: accountProfile,
        oaath_accounts: accounts,
        signer: { id: "root-signer", kind: "ecdsa", profile: root.credential },
      })
        .setProtectedHeader({ alg: "ES256", kid: "k1" })
        .setIssuer(ISSUER)
        .setAudience(CLIENT)
        .setSubject(account)
        .setIssuedAt()
        .setExpirationTime("10m")
        .sign(privateKey);
    const details = par.get("authorization_details");
    // Login only: no grant, just the identity.
    if (details === null) {
      token = { id_token: await signIn(par.get("nonce")), token_type: "Bearer", scope: "openid" };
      return { code: "code-1", state: par.get("state")!, iss: ISSUER };
    }
    const [detail] = JSON.parse(details);
    if (detail.type === "oaath_operation") {
      const signed = await options.signOperation?.(detail.request);
      token = {
        id_token: await signIn(par.get("nonce")),
        token_type: "Bearer",
        scope: "openid",
        authorization_details: [{ type: "oaath_operation", signed }],
      };
      return { code: "code-1", state: par.get("state")!, iss: ISSUER };
    }
    const requestedAt = Math.floor(Date.now() / 1000);
    // The relay's compose.
    const request: Record<string, unknown> = {
      version: "oaath.permission-request/v1",
      requestId: parId,
      context: {
        version: "oaath.workspace-account-context/v1",
        workspaceId: account,
        workspaceKind: "personal",
        accountId: account,
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
      chainId,
      account,
    }).sign(root.key, requestedAt);
    const { installApproval, ...rest } = decision;
    const idToken = await signIn(par.get("nonce"));
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
    return { code: "code-1", state: par.get("state")!, iss: ISSUER };
  }

  /** The redirect page posting the response back to its opener. */
  async function answerPopup(href: string, popup: object) {
    const query = await authorize(href);
    const event = new Event("message");
    Object.defineProperties(event, {
      data: { value: { type: RESPONSE, url: `${REDIRECT}?${new URLSearchParams(query)}` } },
      origin: { value: ORIGIN },
      source: { value: popup },
    });
    window.dispatchEvent(event);
  }

  /** An extension-style launcher: the portal's redirect URL, returned directly. */
  const launch = vi.fn(
    async (href: string) => `${REDIRECT}?${new URLSearchParams(await authorize(href))}`,
  );

  const issuerFetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
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
    const invalidating = /^\/oauth\/grants\/([^/]+)\/invalidate$/u.exec(url.pathname);
    if (invalidating) {
      invalidations.push({
        grantId: decodeURIComponent(invalidating[1] ?? ""),
        body: JSON.parse(String(init?.body)),
      });
      if (options.invalidation === "down") throw new TypeError("fetch failed");
      return json(
        { evidenceHash: `0x${"ee".repeat(32)}`, invalidatedAt: 0 },
        options.invalidation ?? 200,
      );
    }
    if (url.pathname === "/oauth/token") {
      tokenCalls.count += 1;
      if (behaviour !== "pending") return json(token);
      if (redeemed) return json({ error: "invalid_grant" }, 400);
      if (rootDecision === null) return json({ error: "authorization_pending" }, 400);
      if (rootDecision === "reject") return json({ error: "access_denied" }, 400);
      redeemed = true;
      return json(token);
    }
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
              setTimeout(() => void answerPopup(value, popup), 0);
          },
        },
      };
      popups.push(popup);
      return popup;
    }),
  });
  // Only the issuer is faked; any other URL (a local chain) keeps the real fetch.
  const realFetch = globalThis.fetch;
  vi.stubGlobal("window", window);
  vi.stubGlobal("location", { origin: ORIGIN, href: `${ORIGIN}/` });
  vi.stubGlobal("fetch", (input: string | URL | Request, init?: RequestInit) =>
    String(input instanceof Request ? input.url : input).startsWith(ISSUER)
      ? issuerFetch(input, init)
      : realFetch(input, init),
  );
  const approvals = {
    kind: "oauth" as const,
    issuer: ISSUER,
    clientId: CLIENT,
    redirectUri: REDIRECT,
  };
  const decide = (decision: "approve" | "reject") => {
    rootDecision = decision;
  };
  return { approvals, window, popups, pars, root, launch, decide, tokenCalls, invalidations };
}
