/**
 * The built portal in headless Chrome against a stub relay whose responses are
 * the typed `src/api.ts` shapes. The stub accepts any sign-in proof; the real
 * relay verifies them in `login.e2e.ts`.
 */
import { generateKeyPairSync } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  hashOwnerCredentialProfile,
  hashPermissionRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { prepareDerivedAccountPermissionApproval } from "@oaath/sdk/kernel";
import puppeteer, { type Browser, type Page } from "puppeteer-core";
import { hashTypedData, keccak256 } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  ChallengeResponse,
  CreateAccountResponse,
  DecisionRequest,
  GrantDetail,
  IdentifiedSigner,
  PolicyTemplate,
  PortalAccount,
  PortalLink,
  PortalTransaction,
  PrepareGrantResponse,
  RedirectResponse,
  RegisterSignerResponse,
  SignerAccountsResponse,
  SignInResponse,
} from "../src/api.js";
import type { RememberedSigner } from "../src/signers.js";

const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const CAPTURES = process.env.OAATH_PORTAL_CAPTURES;
const WALLET_SIGNER: RememberedSigner = {
  signer_id: "signer-wallet",
  kind: "wallet",
  label: "Test Wallet",
  profile: {
    version: "oaath.owner-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"11".repeat(20)}`,
  },
  credentialId: null,
  rdns: "test.wallet",
  lastUsedAt: 1,
};

/** A resident credential the relay knows, as if enrolled in another browser. */
const KNOWN_KEY = generateKeyPairSync("ec", { namedCurve: "P-256" });
const KNOWN_CREDENTIAL_BYTES = Buffer.from("known-passkey-0001");
const KNOWN_CREDENTIAL = KNOWN_CREDENTIAL_BYTES.toString("base64url");
const KNOWN_PUBLIC_KEY = `0x${KNOWN_KEY.publicKey
  .export({ type: "spki", format: "der" })
  .subarray(-65)
  .toString("hex")}` as const;

interface Call {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
}

let server: Server;
let origin: string;
let browser: Browser;
const calls: Call[] = [];
const accounts = new Map<string, PortalAccount[]>();

function json(response: import("node:http").ServerResponse, status: number, body: unknown) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

/** One grant the dapp requests, as the relay composes and prepares it. */
const NOW = Math.floor(Date.now() / 1000);
const GRANT_DETAIL = {
  type: "oaath_grant",
  signer: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"d1".repeat(20)}`,
  },
  policy: {
    version: "oaath.grant-policy/v2",
    calls: [
      {
        target: `0x${"aa".repeat(20)}`,
        selector: "0xa9059cbb",
        valueLimit: "500000000000000000",
        argumentEquals: [],
      },
      {
        target: `0x${"bb".repeat(20)}`,
        selector: "0xdeadbeef",
        valueLimit: "0",
        argumentEquals: [],
      },
    ],
    validAfter: NOW,
    validUntil: NOW + 3600,
    perChainOperationLimit: { count: 3, intervalSeconds: null },
  },
  chains: [8453],
  expires_at: NOW + 7200,
  device_id: "device-1",
} satisfies GrantDetail;
const ROOT_ACCOUNT: PortalAccount = {
  account_id: "account-grant-root",
  address: `0x${"ab".repeat(20)}`,
  role: "root",
  status: "active",
  profile: {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "kernel_factory",
    entryPoint: { version: "0.9" },
    ownerCredential: WALLET_SIGNER.profile,
  },
};
const GRANT_SIGNER: RememberedSigner = { ...WALLET_SIGNER, signer_id: "signer-grant" };
const NONCE = "ab".repeat(32);
const SIWE_MESSAGE = "oaath sign-in message";

function grantPreparation(account: PortalAccount): PrepareGrantResponse {
  const request = parsePermissionRequest({
    version: "oaath.permission-request/v2",
    requestId: "par-grant",
    context: {
      version: "oaath.workspace-account-context/v1",
      workspaceId: "personal-1",
      workspaceKind: "personal",
      accountId: "account-1",
    },
    application: {
      applicationId: "client-1",
      clientId: "client-1",
      origin: "https://dapp.example",
      deviceId: "device-1",
    },
    chainScope: "all",
    logicalAccount: account.profile,
    operatorCredential: GRANT_DETAIL.signer,
    policy: GRANT_DETAIL.policy,
    requestedAt: NOW,
    expiresAt: GRANT_DETAIL.expires_at,
    sessionSigner: null,
  });
  return {
    permission_request: request,
    request_hash: hashPermissionRequest(request),
    approved_policy: request.policy,
    signing_request: prepareDerivedAccountPermissionApproval({
      request,
      chainId: 8453,
      account: account.address,
    }).signingRequest,
  };
}

function grantTransaction(id: string): PortalTransaction {
  return {
    transaction_id: id,
    client_id: "client-1",
    client_name: "Example Dapp",
    redirect_origin: origin,
    authorization_details: [GRANT_DETAIL],
    expires_at: NOW + 600,
  };
}

/** A link from a second device's passkey to ROOT_ACCOUNT, as the relay reads it. */
function portalLink(id: string): PortalLink {
  const profile = {
    version: "oaath.owner-credential-profile/v1",
    kind: "webauthn",
    publicKey: KNOWN_PUBLIC_KEY,
    authenticatorIdHash: keccak256(KNOWN_CREDENTIAL_BYTES),
  } as const;
  const message = {
    account: ROOT_ACCOUNT.address,
    signerProfileHash: hashOwnerCredentialProfile(profile),
    role: "permission",
    issuedAt: NOW,
    expiresAt: NOW + 3600,
    nonce: id,
  } as const;
  const types = {
    MembershipApproval: [
      { name: "account", type: "address" },
      { name: "signerProfileHash", type: "bytes32" },
      { name: "role", type: "string" },
      { name: "issuedAt", type: "uint64" },
      { name: "expiresAt", type: "uint64" },
      { name: "nonce", type: "string" },
    ],
  } as const;
  const digest = hashTypedData({
    domain: { name: "OAAth", version: "1" },
    types,
    primaryType: "MembershipApproval",
    message: { ...message, issuedAt: BigInt(NOW), expiresAt: BigInt(NOW + 3600) },
  });
  return {
    link_id: id,
    status: "pending",
    account_id: ROOT_ACCOUNT.account_id,
    address: ROOT_ACCOUNT.address,
    signer: {
      signer_id: "signer-second-device",
      kind: "webauthn",
      profile,
      profile_hash: message.signerProfileHash,
    },
    label: "Second device",
    role: "permission",
    expires_at: NOW + 3600,
    typed_data: {
      types: {
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
        ],
        ...types,
      },
      primaryType: "MembershipApproval",
      domain: { name: "OAAth", version: "1" },
      message,
    },
    // A relay that shows one signer but asks for a signature over another.
    digest: id === "link-tampered" ? `0x${"77".repeat(32)}` : digest,
    grant_id: null,
  };
}

const PAYMENTS: PolicyTemplate = {
  template_id: "template-payments",
  name: "Payments",
  policy: {
    calls: [{ target: `0x${"aa".repeat(20)}`, selector: "0xa9059cbb", valueLimit: "0" }],
    perChainOperationLimit: { count: 10, intervalSeconds: 86_400 },
  },
  lifetime_seconds: 30 * 86_400,
  created_at: NOW,
  updated_at: NOW,
};

async function stubRelay(path: string, method: string, body: unknown) {
  const link = /^\/portal\/links\/(link-[\w-]+)$/u.exec(path);
  if (link?.[1] && method === "GET") return portalLink(link[1]);
  if (path === `/portal/accounts/${ROOT_ACCOUNT.account_id}/policies` && method === "GET")
    return { policies: [PAYMENTS] };
  // A relay that prepares the dapp's grant instead of the member's.
  if (path === "/portal/links/link-template/prepare" && method === "POST")
    return grantPreparation(ROOT_ACCOUNT);
  const grant = /^\/portal\/transactions\/(par-grant(?:-tampered)?)(\/prepare)?$/u.exec(path);
  if (grant?.[1] && !grant[2] && method === "GET") return grantTransaction(grant[1]);
  if (grant?.[1] && grant[2] && method === "POST") {
    const prepared = grantPreparation(ROOT_ACCOUNT);
    return grant[1] === "par-grant-tampered"
      ? {
          ...prepared,
          signing_request: { ...prepared.signing_request, expectedDigest: `0x${"66".repeat(32)}` },
        }
      : prepared;
  }
  if (path === "/portal/transactions/par-1" && method === "GET")
    return {
      transaction_id: "par-1",
      client_id: "client-1",
      client_name: "Example Dapp",
      redirect_origin: origin,
      authorization_details: [],
      expires_at: Math.floor(Date.now() / 1000) + 600,
    } satisfies PortalTransaction;
  if (path === "/portal/sessions/challenge" && method === "POST")
    return {
      nonce: NONCE,
      expires_at: NOW + 300,
      ...((body as { signer_id?: string }).signer_id ? { message: SIWE_MESSAGE } : {}),
    } satisfies ChallengeResponse;
  if (path === "/portal/sessions" && method === "POST")
    return {
      signer_id: (body as { signer_id: string }).signer_id,
      expires_at: NOW + 1800,
    } satisfies SignInResponse;
  if (path === "/portal/signers" && method === "POST")
    return { signer_id: "signer-passkey" } satisfies RegisterSignerResponse;
  const listed = /^\/portal\/signers\/([\w-]+)\/accounts$/u.exec(path);
  if (listed?.[1] && method === "GET")
    return { accounts: accounts.get(listed[1]) ?? [] } satisfies SignerAccountsResponse;
  if (path === "/portal/accounts" && method === "POST") {
    const signer = (body as { root_signer_id: string }).root_signer_id;
    const created = {
      account_id: `account-${signer}`,
      address: `0x${"ab".repeat(20)}`,
      profile: {
        version: "oaath.kernel-account-profile/v1",
        kind: "kernel",
        accountIndex: "0",
        kernelVersion: "0.4.0",
        factoryRoute: "kernel_factory",
        entryPoint: { version: "0.9" },
        ownerCredential: WALLET_SIGNER.profile,
      },
    } satisfies CreateAccountResponse;
    accounts.set(signer, [{ ...created, role: "root", status: "active" }]);
    return created;
  }
  if (/^\/portal\/transactions\/par-[\w-]+\/decision$/u.test(path) && method === "POST")
    return {
      redirect:
        (body as DecisionRequest).outcome === "cancelled"
          ? `${origin}/dapp/callback?error=access_denied&state=s`
          : `${origin}/dapp/callback?code=code-1&state=s`,
    } satisfies RedirectResponse;
  if (path === `/portal/signers/by-credential/${KNOWN_CREDENTIAL}` && method === "GET")
    return {
      signer_id: "signer-known-passkey",
      kind: "webauthn",
      profile: {
        version: "oaath.owner-credential-profile/v1",
        kind: "webauthn",
        publicKey: KNOWN_PUBLIC_KEY,
        authenticatorIdHash: keccak256(KNOWN_CREDENTIAL_BYTES),
      },
    } satisfies IdentifiedSigner;
  return null;
}

/** A contract with code but no Kernel implementation slot, on the stub chain. */
const PLAIN_CONTRACT = `0x${"c0".repeat(20)}`;

/** The stub chain for the import screen: one plain contract, nothing else deployed. */
function stubChain(body: unknown): unknown {
  const answer = (call: { id: unknown; method: string; params: unknown[] }) => {
    const result =
      call.method === "eth_chainId"
        ? "0x66eee"
        : call.method === "eth_getCode"
          ? String(call.params[0]).toLowerCase() === PLAIN_CONTRACT
            ? "0x6000"
            : "0x"
          : call.method === "eth_getStorageAt"
            ? `0x${"00".repeat(32)}`
            : null;
    return { jsonrpc: "2.0", id: call.id, result };
  };
  return Array.isArray(body) ? body.map(answer) : answer(body as Parameters<typeof answer>[0]);
}

beforeAll(async () => {
  await access(join(DIST, "index.html"));
  accounts.set(GRANT_SIGNER.signer_id, [
    ROOT_ACCOUNT,
    {
      ...ROOT_ACCOUNT,
      account_id: "account-grant-member",
      address: `0x${"cd".repeat(20)}`,
      role: "permission",
    },
  ]);
  server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    let raw = "";
    for await (const chunk of request) raw += chunk;
    const body = raw ? (JSON.parse(raw) as unknown) : null;
    if (url.pathname.startsWith("/portal/")) {
      calls.push({ method: request.method ?? "GET", path: url.pathname, body });
      const result = await stubRelay(url.pathname, request.method ?? "GET", body);
      return result === null
        ? json(response, 404, { error: { code: "relay_not_found" } })
        : json(response, 200, result);
    }
    if (url.pathname === "/rpc/421614") return json(response, 200, stubChain(body));
    if (url.pathname.startsWith("/dapp/")) {
      response.writeHead(200, { "content-type": "text/html" });
      return response.end("<!doctype html><title>dapp</title>");
    }
    const file = url.pathname.startsWith("/assets/") ? url.pathname : "/index.html";
    const type = file.endsWith(".js")
      ? "text/javascript"
      : file.endsWith(".css")
        ? "text/css"
        : "text/html";
    try {
      const content = await readFile(join(DIST, file));
      response.writeHead(200, { "content-type": type });
      response.end(content);
    } catch {
      response.writeHead(404).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  // localhost is a secure context, so WebAuthn runs without TLS.
  origin = `http://localhost:${address.port}`;
  const candidates = [
    process.env.PUPPETEER_EXECUTABLE_PATH,
    process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ].filter((path): path is string => Boolean(path));
  let executablePath: string | undefined;
  for (const path of candidates) {
    try {
      await access(path);
      executablePath = path;
      break;
    } catch {}
  }
  if (!executablePath) throw new Error("Chrome is required for the portal browser test");
  browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: ["--no-sandbox", "--disable-background-networking"],
  });
});

afterAll(async () => {
  await browser?.close();
  await new Promise((resolve) => server?.close(resolve));
});

/**
 * An EIP-6963 wallet in every document of `page`, recording each method and
 * `personal_sign` request. It signs nothing real: the stub relay accepts any proof.
 */
async function installWallet(page: Page, name = "Test Wallet", rdns = "test.wallet") {
  await page.evaluateOnNewDocument(
    (wallet: { name: string; rdns: string; address: string }) => {
      const methods: string[] = [];
      const signed: unknown[] = [];
      Object.assign(window, { walletMethods: methods, walletSigned: signed });
      const provider = {
        request: async ({ method, params }: { method: string; params?: unknown }) => {
          methods.push(method);
          if (method === "personal_sign") {
            signed.push(params);
            return `0x${"99".repeat(65)}`;
          }
          return [wallet.address];
        },
      };
      window.addEventListener("eip6963:requestProvider", () =>
        window.dispatchEvent(
          new CustomEvent("eip6963:announceProvider", {
            detail: Object.freeze({
              info: { uuid: wallet.rdns, name: wallet.name, icon: "", rdns: wallet.rdns },
              provider,
            }),
          }),
        ),
      );
    },
    {
      name,
      rdns,
      address: `0x${(rdns === "test.wallet" ? "11" : "22").repeat(20)}`,
    },
  );
}

function walletMethods(page: Page) {
  return page.evaluate(() => (window as unknown as { walletMethods: string[] }).walletMethods);
}

async function openPortal(
  seed: readonly RememberedSigner[],
  transaction = "par-1",
  wallet = true,
): Promise<Page> {
  const page = await browser.newPage();
  await page.setViewport({ width: 390, height: 844 });
  if (wallet) await installWallet(page);
  await page.evaluateOnNewDocument((signers: string) => {
    localStorage.setItem("oaath.portal.signers/v1", signers);
  }, JSON.stringify(seed));
  await page.goto(
    `${origin}/authorize?client_id=client-1&request_uri=urn:ietf:params:oauth:request_uri:${transaction}`,
  );
  await page.waitForSelector("#signer-heading");
  return page;
}

async function clickText(page: Page, text: string) {
  const button = await page.waitForSelector(`::-p-text(${text})`);
  await button?.click();
}

async function capture(page: Page, name: string) {
  if (CAPTURES) await page.screenshot({ path: join(CAPTURES, `${name}.png`), fullPage: true });
}

describe("portal in Chrome", () => {
  it("always shows the signer screen, then creates an account and returns to the dapp", async () => {
    const page = await openPortal([WALLET_SIGNER]);
    expect(await page.$eval("#signer-heading", (node) => node.textContent)).toBe("Sign in with…");
    expect(await page.$("::-p-text(Test Wallet)")).not.toBeNull();
    expect(await page.$("::-p-text(Add signer)")).not.toBeNull();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await capture(page, "1-signers");

    await clickText(page, "Test Wallet");
    await page.waitForSelector("::-p-text(This signer has no account yet.)");
    expect(
      await page.$eval(
        "::-p-text(Link to an existing account)",
        (node) => (node as HTMLButtonElement).disabled,
      ),
    ).toBe(false);
    await capture(page, "2-accounts-empty");
    await clickText(page, "Create account");
    await page.waitForSelector("::-p-text(0xabab…abab)");
    await capture(page, "3-account-created");
    expect(await walletMethods(page)).toEqual(["eth_requestAccounts", "personal_sign"]);
    await Promise.all([page.waitForNavigation(), clickText(page, "0xabab…abab")]);
    expect(page.url()).toBe(`${origin}/dapp/callback?code=code-1&state=s`);
    expect(calls.filter((call) => call.method === "POST")).toEqual([
      {
        method: "POST",
        path: "/portal/sessions/challenge",
        body: { signer_id: "signer-wallet" },
      },
      {
        method: "POST",
        path: "/portal/sessions",
        body: { signer_id: "signer-wallet", nonce: NONCE, signature: `0x${"99".repeat(65)}` },
      },
      { method: "POST", path: "/portal/accounts", body: { root_signer_id: "signer-wallet" } },
      {
        method: "POST",
        path: "/portal/transactions/par-1/decision",
        body: {
          signer_id: "signer-wallet",
          account_id: "account-signer-wallet",
          outcome: "approved",
        },
      },
    ]);
    await page.close();
  });

  it("adds a passkey signer and signs it in with an assertion over the relay's nonce", async () => {
    calls.length = 0;
    // No wallet is announced, so the empty state is the settled list, not the
    // frame before EIP-6963 discovery answers.
    const page = await openPortal([], "par-1", false);
    const session = await page.createCDPSession();
    await session.send("WebAuthn.enable");
    await session.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });
    expect(await page.$("::-p-text(No signers on this browser yet.)")).not.toBeNull();
    await clickText(page, "Add signer");
    await page.waitForSelector("::-p-text(No browser wallet found.)");
    expect(await page.$("::-p-text(Phone)")).toBeNull();
    await capture(page, "4-add-signer");
    await clickText(page, "New passkey");
    await page.waitForSelector("#account-heading");
    const signIn = calls.find((call) => call.path === "/portal/sessions");
    expect(signIn?.body).toMatchObject({
      signer_id: "signer-passkey",
      nonce: NONCE,
      signature: expect.stringMatching(/^0x[0-9a-f]+$/u),
    });
    const [register] = calls.filter((call) => call.path === "/portal/signers");
    if (!register) throw new Error("the passkey signer was not registered");
    const profile = (register.body as { profile: Record<string, string> }).profile;
    expect(profile.version).toBe("oaath.owner-credential-profile/v1");
    expect(profile.kind).toBe("webauthn");
    expect(profile.publicKey).toMatch(/^0x04[0-9a-f]{128}$/u);
    const remembered = await page.evaluate(() => localStorage.getItem("oaath.portal.signers/v1"));
    expect(JSON.parse(remembered ?? "[]")[0]).toMatchObject({
      signer_id: "signer-passkey",
      kind: "passkey",
    });
    await page.close();
  });

  it("connects an EIP-6963 wallet and signs in with personal_sign of the relay's message", async () => {
    calls.length = 0;
    const page = await browser.newPage();
    await installWallet(page, "Fixture Wallet", "test.fixture");
    await page.goto(
      `${origin}/authorize?client_id=client-1&request_uri=urn:ietf:params:oauth:request_uri:par-1`,
    );
    await clickText(page, "Add signer");
    await clickText(page, "Fixture Wallet");
    await page.waitForSelector("#account-heading");
    expect(await walletMethods(page)).toEqual([
      "eth_requestAccounts",
      "eth_requestAccounts",
      "personal_sign",
    ]);
    expect(
      await page.evaluate(() => (window as unknown as { walletSigned: unknown[] }).walletSigned),
    ).toEqual([[`0x${Buffer.from(SIWE_MESSAGE).toString("hex")}`, `0x${"22".repeat(20)}`]]);
    const [register] = calls.filter((call) => call.path === "/portal/signers");
    expect(register?.body).toEqual({
      profile: {
        version: "oaath.owner-credential-profile/v1",
        kind: "ecdsa",
        address: `0x${"22".repeat(20)}`,
      },
    });
    await page.close();
  });

  async function withResidentPasskey(page: Page, credential: Buffer) {
    const session = await page.createCDPSession();
    await session.send("WebAuthn.enable");
    const { authenticatorId } = await session.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });
    await session.send("WebAuthn.addCredential", {
      authenticatorId,
      credential: {
        credentialId: credential.toString("base64"),
        isResidentCredential: true,
        rpId: "localhost",
        privateKey: KNOWN_KEY.privateKey
          .export({ type: "pkcs8", format: "der" })
          .toString("base64"),
        userHandle: Buffer.from("user").toString("base64"),
        signCount: 0,
      },
    });
  }

  it("recognises a passkey from another browser by its credential ID alone", async () => {
    calls.length = 0;
    const page = await openPortal([]);
    await withResidentPasskey(page, KNOWN_CREDENTIAL_BYTES);
    await clickText(page, "Use a passkey from another device or browser");
    // The account list has loaded only once its request has been answered.
    await page.waitForSelector("::-p-text(This signer has no account yet.)");
    // One assertion both names the passkey and signs the relay's nonce.
    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
      "GET /portal/transactions/par-1",
      "POST /portal/sessions/challenge",
      `GET /portal/signers/by-credential/${KNOWN_CREDENTIAL}`,
      "POST /portal/sessions",
      "GET /portal/signers/signer-known-passkey/accounts",
    ]);
    const remembered = await page.evaluate(() => localStorage.getItem("oaath.portal.signers/v1"));
    expect(JSON.parse(remembered ?? "[]")[0]).toMatchObject({
      signer_id: "signer-known-passkey",
      kind: "passkey",
      credentialId: KNOWN_CREDENTIAL,
      profile: { kind: "webauthn", publicKey: KNOWN_PUBLIC_KEY },
    });
    await page.close();
  });

  it("says an unknown passkey is not registered with OAAth", async () => {
    const page = await openPortal([]);
    await withResidentPasskey(page, Buffer.from("unknown-passkey-01"));
    await clickText(page, "Use a passkey from another device or browser");
    const alert = await page.waitForSelector("[role=alert]");
    expect(await alert?.evaluate((node) => node.textContent)).toContain(
      "isn't registered with OAAth",
    );
    await page.close();
  });

  it("cancels from the account screen with access_denied", async () => {
    calls.length = 0;
    const page = await openPortal([WALLET_SIGNER]);
    await clickText(page, "Test Wallet");
    await page.waitForSelector("#account-heading");
    // The account the first test created is listed with its role as "Owner".
    await page.waitForSelector("::-p-text(Smart account · Owner)");
    await Promise.all([page.waitForNavigation(), clickText(page, "Cancel and return to the app")]);
    expect(new URL(page.url()).searchParams.get("error")).toBe("access_denied");
    expect(calls.at(-1)).toEqual({
      method: "POST",
      path: "/portal/transactions/par-1/decision",
      body: { outcome: "cancelled" },
    });
    await page.close();
  });

  it("shows a grant's signer and policy and offers only accounts the signer owns", async () => {
    calls.length = 0;
    const page = await openPortal([GRANT_SIGNER], "par-grant");
    await clickText(page, "Test Wallet");
    await page.waitForSelector("::-p-text(0xabab…abab)");
    // A signer that is not the root cannot approve a grant, so it is not offered.
    expect(await page.$("::-p-text(0xcdcd…cdcd)")).toBeNull();
    await capture(page, "5-grant-accounts");
    await clickText(page, "0xabab…abab");
    const review = await page.waitForSelector(".review");
    const text = await review?.evaluate((node) => (node as HTMLElement).innerText);
    expect(text).toContain(`Ethereum key 0x${"d1".repeat(20)}`);
    expect(text).toContain("transfer");
    expect(text).toContain("Sends up to 0.5 ETH");
    expect(text).toContain("0xdeadbeef");
    expect(text).toContain("Up to 3 operations per chain in total");
    expect(text).toContain("Base");
    expect(await page.$("::-p-text(the only signature OAAth ever asks for)")).not.toBeNull();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await capture(page, "6-grant-review");
    expect(calls.at(-1)).toEqual({
      method: "POST",
      path: "/portal/transactions/par-grant/prepare",
      body: { signer_id: "signer-grant", account_id: "account-grant-root" },
    });
    await page.close();
  });

  it("refuses a signing request whose digest it did not derive, before any wallet prompt", async () => {
    calls.length = 0;
    const page = await openPortal([GRANT_SIGNER], "par-grant-tampered");
    await clickText(page, "Test Wallet");
    await clickText(page, "0xabab…abab");
    await page.waitForSelector("::-p-text(Approve and sign):not([disabled])");
    await clickText(page, "Approve and sign");
    const alert = await page.waitForSelector("[role=alert]");
    expect(await alert?.evaluate((node) => node.textContent)).toContain("will not sign it");
    // Only the sign-in was signed; the grant typed data never reached the wallet.
    expect(await walletMethods(page)).toEqual(["eth_requestAccounts", "personal_sign"]);
    expect(calls.some((call) => call.path.endsWith("/decision"))).toBe(false);
    await page.close();
  });

  it("shows the owner a link request and refuses to sign a digest it did not derive", async () => {
    const page = await browser.newPage();
    await page.setViewport({ width: 390, height: 844 });
    await installWallet(page);
    await page.evaluateOnNewDocument(
      (signers: string) => {
        localStorage.setItem("oaath.portal.signers/v1", signers);
      },
      JSON.stringify([GRANT_SIGNER]),
    );
    await page.goto(`${origin}/link/link-tampered`);
    await clickText(page, "Test Wallet");
    await page.waitForSelector("::-p-text(Add a signer to your account)");
    const review = await page.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(review).toContain(ROOT_ACCOUNT.address);
    expect(review).toContain("Passkey “Second device”");
    expect(review).toContain("Sign in only");
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await capture(page, "7-link-review");
    const before = calls.length;
    await clickText(page, "Approve and sign");
    await page.waitForSelector("::-p-text(doesn't match what you were shown)");
    expect(await walletMethods(page)).not.toContain("eth_signTypedData_v4");
    expect(calls.slice(before).some((call) => call.path.endsWith("/approve"))).toBe(false);
    await page.close();
  });

  it("offers the owner's templates and refuses to sign a grant that is not the member's", async () => {
    const page = await browser.newPage();
    await page.setViewport({ width: 390, height: 844 });
    await installWallet(page);
    await page.evaluateOnNewDocument(
      (signers: string) => {
        localStorage.setItem("oaath.portal.signers/v1", signers);
      },
      JSON.stringify([GRANT_SIGNER]),
    );
    await page.goto(`${origin}/link/link-template`);
    await clickText(page, "Test Wallet");
    await clickText(page, "spend within “Payments”");
    const review = await page.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(review).toContain("1 call · 10 operations per chain a day · 30 days");
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await capture(page, "8-link-template");
    const before = calls.length;
    await clickText(page, "Approve and sign");
    await page.waitForSelector("::-p-text(doesn't match what you were shown)");
    expect(await walletMethods(page)).not.toContain("eth_signTypedData_v4");
    expect(calls.slice(before).some((call) => call.path.endsWith("/approve"))).toBe(false);
    await page.close();
  });
});

describe("importing an existing account", () => {
  it("explains each refusal at phone width without overflowing", async () => {
    const page = await openPortal([WALLET_SIGNER]);
    await clickText(page, "Test Wallet");
    await page.waitForSelector("#account-heading");
    await clickText(page, "Import an existing account");
    async function check(address: string) {
      await page.waitForSelector("#import-address");
      await page.$eval("#import-address", (node) => {
        (node as HTMLInputElement).value = "";
      });
      await page.type("#import-address", address);
      await clickText(page, "Check account");
      await page.waitForSelector(".check-fail, .check-unknown");
      return page.$eval("#import-account", (node) => (node as HTMLElement).innerText);
    }
    expect(await check("0x1234")).toContain("Enter the account's 0x address");
    expect(await check(`0x${"12".repeat(20)}`)).toContain(
      "No contract is deployed at this address on Arbitrum Sepolia.",
    );
    expect(await check(PLAIN_CONTRACT)).toContain(
      "This contract is not a Kernel smart account: it has no upgradeable implementation.",
    );
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await capture(page, "5-import-refused");
    await page.close();
  });
});
