/**
 * Login with OAAth end to end, with no stub on the authorization path:
 *
 * - the real Rust relay binary, configured as production runs it (no
 *   OAATH_CONFIG, kid from the key thumbprint) with the memory store and a
 *   throwaway ES256 key;
 * - the real portal Worker module, run in Node in front of the built SPA and
 *   bound to that relay (the Workers VPC binding becomes a loopback fetch);
 * - the examples/oauth-login dapp on another origin, whose page calls the
 *   SDK's `loginWithOAAth` (and, on a third origin configured with a chain,
 *   `createOAAth({ approvals: { kind: "oauth" } })` and `requestPermission`) and
 *   whose redirect page runs `completeOAAthLogin`;
 * - headless Chrome clicking through the SDK's popup.
 *
 * The SDK verifies the id_token; the test verifies it again against
 * `/oauth/jwks` with `jose`.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { access, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { kernelDeployment } from "@oaath/sdk/kernel";
import { calculateJwkThumbprint, createRemoteJWKSet, type JWK, jwtVerify } from "jose";
import puppeteer, { type Browser, type Page } from "puppeteer-core";
import { decodeEventLog, encodeFunctionData, hashTypedData, recoverAddress, toHex } from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker, { type Env, ORIGIN } from "../worker/index.js";

const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const RELAY_DIR = fileURLToPath(new URL("../../relay", import.meta.url));
/** The fixture wallet's key: it signs in (SIWE) and signs a grant's root approval. */
const WALLET = privateKeyToAccount(`0x${"5a".repeat(32)}`);
const WALLET_ADDRESS = WALLET.address.toLowerCase() as `0x${string}`;
/** Every EIP-712 approval the fixture wallet signed: logins ask for none. */
let walletSignatures = 0;
const EXAMPLE = fileURLToPath(new URL("../../examples/oauth-login/server.mjs", import.meta.url));
const GRANT_DEMO = fileURLToPath(
  new URL("../../examples/oauth-grant-demo/server.mjs", import.meta.url),
);
const ANVIL = fileURLToPath(
  new URL("../../packages/testing/src/anvil-process.mjs", import.meta.url),
);
const V33 = fileURLToPath(
  new URL("../../packages/sdk/test/fixtures/kernel-v33-deployments.json", import.meta.url),
);

let browser: Browser;
let relay: ReturnType<typeof spawn> | undefined;
const servers: Server[] = [];
const closers: (() => Promise<void>)[] = [];
let portal: string;
let dapp: string;
/** The same example with a chain and a permission: its page requests Grants. */
let grantDapp: string;
let relayBase: string;
/** The production default kid: the id_token key's RFC 7638 thumbprint. */
let idTokenKid: string;

async function listen(handler: (request: IncomingMessage, response: ServerResponse) => void) {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  return address.port;
}

async function freePort() {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  if (!address || typeof address === "string") throw new Error("no port");
  return address.port;
}

async function firstExisting(paths: readonly (string | undefined)[]) {
  for (const path of paths) {
    if (!path) continue;
    try {
      await access(path);
      return path;
    } catch {}
  }
  return undefined;
}

/** Starts the relay binary on loopback with an issuer equal to the portal origin. */
async function startRelay(issuer: string) {
  const cargo =
    (await firstExisting([process.env.CARGO, join(homedir(), ".cargo/bin/cargo")])) ?? "cargo";
  const build = spawnSync(cargo, ["build", "-q", "-p", "oaath-relay"], {
    cwd: RELAY_DIR,
    stdio: "inherit",
  });
  if (build.status !== 0) throw new Error("cargo build -p oaath-relay failed");
  const work = await mkdtemp(join(tmpdir(), "oaath-portal-e2e-"));
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  await writeFile(join(work, "id-token.pem"), privateKey.export({ type: "pkcs8", format: "pem" }));
  idTokenKid = await calculateJwkThumbprint(publicKey.export({ format: "jwk" }) as JWK);
  const port = await freePort();
  relay = spawn(join(RELAY_DIR, "target/debug/oaath-relay"), [], {
    stdio: ["ignore", "ignore", "inherit"],
    env: {
      PATH: process.env.PATH ?? "",
      RUST_LOG: "warn",
      OAATH_LISTEN: `127.0.0.1:${port}`,
      OAATH_KMS_KEY: randomBytes(32).toString("hex"),
      OAATH_ISSUER: issuer,
      OAATH_ID_TOKEN_KEY: join(work, "id-token.pem"),
    },
  });
  const base = `http://127.0.0.1:${port}`;
  for (let attempt = 0; ; attempt += 1) {
    try {
      if ((await fetch(`${base}/.well-known/openid-configuration`)).ok) return base;
    } catch {}
    if (attempt > 200 || relay.exitCode !== null) throw new Error("the relay did not start");
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/** The portal origin: Node's HTTP server in front of the real Worker module. */
async function startPortal() {
  const env: Env = {
    ASSETS: {
      async fetch(request) {
        const path = new URL(request.url).pathname;
        try {
          const body = await readFile(join(DIST, path === "/" ? "index.html" : path));
          const type = path.endsWith(".js")
            ? "text/javascript"
            : path.endsWith(".css")
              ? "text/css"
              : "text/html";
          return new Response(new Uint8Array(body), { headers: { "content-type": type } });
        } catch {
          return new Response("Not found", { status: 404 });
        }
      },
    },
    RELAY: {
      fetch(request) {
        const url = new URL(request.url);
        return fetch(`${relayBase}${url.pathname}${url.search}`, {
          method: request.method,
          headers: request.headers,
          body: request.body,
          redirect: "manual",
          duplex: "half",
        } as RequestInit);
      },
    },
  };
  const port = await listen(async (incoming, outgoing) => {
    const local = `http://localhost:${port}`;
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (typeof value !== "string") continue;
      // The Worker pins its public origin; this host stands in for it.
      headers.set(name, name === "origin" && value === local ? ORIGIN : value);
    }
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) chunks.push(chunk as Buffer);
    const response = await worker.fetch(
      new Request(`${ORIGIN}${incoming.url ?? "/"}`, {
        method: incoming.method ?? "GET",
        headers,
        body: chunks.length > 0 ? Buffer.concat(chunks) : null,
      }),
      env,
    );
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      // Plain-http localhost cannot honour the production upgrade directive.
      responseHeaders[name] =
        name === "content-security-policy"
          ? value.replace("; upgrade-insecure-requests", "")
          : value;
    });
    outgoing.writeHead(response.status, responseHeaders);
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  });
  return `http://localhost:${port}`;
}

/** The SDK Grant's policy target: an ERC-20 the dapp may call transfer on. */
const GRANT_TARGET = `0x${"ab".repeat(20)}`;

/** The examples/oauth-login dapp, on another origin than the portal. */
async function startDapp(grants = false) {
  const { startOAuthLoginExample } = (await import(EXAMPLE)) as {
    startOAuthLoginExample(input: {
      issuer: string;
      host: string;
      port: number;
      chains?: unknown;
      permission?: unknown;
    }): Promise<{ url: string; close(): Promise<void> }>;
  };
  const example = await startOAuthLoginExample({
    issuer: portal,
    host: "127.0.0.1",
    port: 0,
    ...(grants
      ? {
          // Requesting and resuming a Grant reads no chain: this port is closed.
          chains: { 421614: { publicRpcUrls: ["http://127.0.0.1:9/"] } },
          permission: {
            chainScope: "all",
            permissions: [
              { calls: [{ target: GRANT_TARGET, selectors: ["0xa9059cbb"], valueLimit: "0" }] },
            ],
            expiresIn: 3600,
            perChainOperationLimit: 5,
          },
        }
      : {}),
  });
  closers.push(example.close);
  return example.url;
}

/**
 * An EIP-6963 wallet in every document of `page`. It answers eth_requestAccounts,
 * and personal_sign and eth_signTypedData_v4 with the fixture key; it records
 * every method asked.
 */
async function installWallet(page: Page) {
  await page.exposeFunction("e2eWalletSignTypedData", (json: string) => {
    walletSignatures += 1;
    return WALLET.sign({ hash: hashTypedData(JSON.parse(json)) });
  });
  await page.exposeFunction("e2eWalletPersonalSign", (raw: `0x${string}`) =>
    WALLET.signMessage({ message: { raw } }),
  );
  await page.evaluateOnNewDocument((address: string) => {
    const methods: string[] = [];
    Object.assign(window, { walletMethods: methods });
    const sign = (window as unknown as { e2eWalletSignTypedData(json: string): Promise<string> })
      .e2eWalletSignTypedData;
    const provider = {
      request: async ({ method, params }: { method: string; params?: [string, string] }) => {
        methods.push(method);
        if (method === "eth_requestAccounts") return [address];
        if (method === "personal_sign" && params?.[1] === address)
          return (
            window as unknown as { e2eWalletPersonalSign(raw: string): Promise<string> }
          ).e2eWalletPersonalSign(params[0]);
        if (method === "eth_signTypedData_v4" && params?.[0] === address)
          return (
            window as unknown as { e2eWalletSignTypedData: typeof sign }
          ).e2eWalletSignTypedData(params[1]);
        throw new Error("unexpected wallet method");
      },
    };
    window.addEventListener("eip6963:requestProvider", () =>
      window.dispatchEvent(
        new CustomEvent("eip6963:announceProvider", {
          detail: Object.freeze({
            info: { uuid: "e2e-wallet", name: "E2E Wallet", icon: "", rdns: "test.e2e" },
            provider,
          }),
        }),
      ),
    );
  }, WALLET_ADDRESS);
}

async function click(page: Page, selector: string) {
  const element = await page.waitForSelector(selector);
  await element?.click();
}

/** Opens the example dapp, ready to log in (its client is registered on load). */
async function openDapp(
  url = dapp,
  ready = "#login:not([disabled])",
  context: Pick<Browser, "newPage"> = browser,
) {
  const page = await context.newPage();
  // The dapp's PAR waits until the popup is instrumented; it is delayed, never altered.
  let release = () => {};
  const instrumented = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/oauth/par")
      void instrumented.then(() => request.continue());
    else void request.continue();
  });
  await page.goto(`${url}/`);
  await page.waitForSelector(ready);
  return { page, release };
}

/**
 * Clicks "Login with OAAth" and returns the SDK's popup once the fixture wallet
 * is installed in it. `rewrite` may replace the dapp callback URL the portal
 * redirects to, standing in for a hostile or confused authorization response.
 */
async function startLogin(
  dappPage: Awaited<ReturnType<typeof openDapp>>,
  rewrite?: (callback: URL) => URL,
  button = "#login",
) {
  const opened = browser.waitForTarget((target) => target.opener() === dappPage.page.target());
  await click(dappPage.page, button);
  const popup = await (await opened).page();
  if (!popup) throw new Error("no login popup");
  await popup.setViewport({ width: 390, height: 844 });
  await installWallet(popup);
  if (rewrite) {
    let rewritten = false;
    await popup.setRequestInterception(true);
    popup.on("request", (request) => {
      const url = new URL(request.url());
      if (!rewritten && url.origin === dapp && url.pathname === "/callback") {
        rewritten = true;
        return void request.respond({
          status: 302,
          headers: { location: rewrite(url).toString() },
        });
      }
      void request.continue();
    });
  }
  dappPage.release();
  await popup.waitForSelector("#signer-heading");
  return popup;
}

/** The dapp's login outcome: "signed-in" or the OaathClientError code. */
async function outcome(page: Page) {
  const result = await page.waitForSelector("#result[data-outcome]");
  return result?.evaluate((node) => (node as HTMLElement).dataset.outcome);
}

/** Chooses the remembered wallet signer and its first account. */
async function signInWithRememberedWallet(popup: Page) {
  await click(popup, "::-p-text(E2E Wallet)");
  await click(popup, "button[aria-label^='Smart account 0x']");
}

beforeAll(async () => {
  await access(join(DIST, "index.html"));
  // The relay's issuer is the portal origin, so the portal listens first.
  portal = await startPortal();
  relayBase = await startRelay(portal);
  dapp = await startDapp();
  grantDapp = await startDapp(true);
  const executablePath = await firstExisting([
    process.env.PUPPETEER_EXECUTABLE_PATH,
    process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ]);
  if (!executablePath) throw new Error("Chrome is required for the portal end-to-end test");
  browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: ["--no-sandbox", "--disable-background-networking"],
  });
});

afterAll(async () => {
  await browser?.close();
  relay?.kill("SIGTERM");
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  await Promise.all(closers.map((close) => close()));
});

describe("Login with OAAth from the SDK against the real relay", () => {
  it("logs in with a wallet signer and a new account, and returns a verifiable id_token", async () => {
    const dappPage = await openDapp();
    const popup = await startLogin(dappPage);
    expect(await popup.$eval("#signer-heading", (node) => node.textContent)).toBe("Sign in with…");
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(E2E Wallet)");
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");
    await click(popup, "::-p-text(Create account)");
    const account = await popup.waitForSelector("button[aria-label^='Smart account 0x']");
    const label = await account?.evaluate((node) => node.getAttribute("aria-label"));
    const shown = /0x[0-9a-f]{40}/u.exec(label ?? "")?.[0];
    expect(shown).toBeDefined();
    // Connecting asks for the account; signing in asks for one SIWE signature.
    expect(
      await popup.evaluate(() => (window as unknown as { walletMethods: string[] }).walletMethods),
    ).toEqual(["eth_requestAccounts", "eth_requestAccounts", "personal_sign"]);
    expect(walletSignatures).toBe(0);
    await account?.click();

    expect(await outcome(dappPage.page)).toBe("signed-in");
    const login: Record<string, unknown> = await dappPage.page.evaluate(() => {
      const value = (window as unknown as { oaathLogin: Record<string, unknown> }).oaathLogin;
      const clientKey = Object.keys(localStorage).find((key) =>
        key.startsWith("oaath-example-client:"),
      );
      return { ...value, clientId: clientKey ? localStorage.getItem(clientKey) : null };
    });
    expect(login.account).toBe(shown);
    expect(login.verified).toBe(true);
    expect(login.signer).toMatchObject({
      kind: "ecdsa",
      profile: { kind: "ecdsa", address: WALLET_ADDRESS },
    });
    // Independent of the SDK's own check: the token verifies against the JWKS.
    const { payload, protectedHeader } = await jwtVerify(
      String(login.idToken),
      createRemoteJWKSet(new URL(`${portal}/oauth/jwks`)),
      { issuer: portal, audience: String(login.clientId), algorithms: ["ES256"] },
    );
    expect(protectedHeader.kid).toBe(idTokenKid);
    expect(payload.sub).toBe(shown);
    expect(payload.verified).toBe(true);
    // The signer's accounts are private: without its session cookie, refused.
    const signerId = (login.signer as { id: string }).id;
    const anonymous = await fetch(`${portal}/portal/signers/${signerId}/accounts`);
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toEqual({ error: { code: "relay_unauthenticated" } });
    await dappPage.page.close();
  });

  it("reports access_denied when the user cancels", async () => {
    const dappPage = await openDapp();
    const popup = await startLogin(dappPage);
    await click(popup, "::-p-text(Cancel and return to the app)");
    expect(await outcome(dappPage.page)).toBe("oaath_client_access_denied");
    await dappPage.page.close();
  });

  it("refuses an authorization response with another login's state", async () => {
    const dappPage = await openDapp();
    const popup = await startLogin(dappPage, (callback) => {
      callback.searchParams.set("state", "another-login");
      return callback;
    });
    await signInWithRememberedWallet(popup);
    expect(await outcome(dappPage.page)).toBe("oaath_client_state_mismatch");
    await dappPage.page.close();
  });

  it("refuses an authorization response from another issuer (RFC 9207)", async () => {
    const dappPage = await openDapp();
    const popup = await startLogin(dappPage, (callback) => {
      callback.searchParams.set("iss", "https://issuer.example");
      return callback;
    });
    await signInWithRememberedWallet(popup);
    expect(await outcome(dappPage.page)).toBe("oaath_client_issuer_mismatch");
    await dappPage.page.close();
  });
});

interface PushedGrant {
  readonly clientId: string;
  readonly requestUri: string;
  readonly verifier: string;
}

/** The dapp PARs a grant for its own ECDSA session key; F2's SDK will do this. */
async function pushGrant(page: Page): Promise<PushedGrant> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return page.evaluate(
    async (input) => {
      const redirectUri = `${location.origin}/callback`;
      const registered = await fetch(`${input.portal}/oauth/clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_name: "E2E Grant Dapp", redirect_uris: [redirectUri] }),
      });
      const { client_id: clientId } = (await registered.json()) as { client_id: string };
      const now = Math.floor(Date.now() / 1000);
      const detail = {
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
              valueLimit: "0",
              argumentEquals: [],
            },
          ],
          validAfter: now,
          validUntil: now + 3600,
          perChainOperationLimit: { count: 5, intervalSeconds: 86400 },
        },
        chains: [421614],
        expires_at: now + 7200,
        device_id: "e2e-device",
      };
      const pushed = await fetch(`${input.portal}/oauth/par`, {
        method: "POST",
        body: new URLSearchParams({
          client_id: clientId,
          redirect_uri: redirectUri,
          response_type: "code",
          code_challenge: input.challenge,
          code_challenge_method: "S256",
          scope: "openid",
          state: "grant-state",
          nonce: "grant-nonce",
          authorization_details: JSON.stringify([detail]),
        }),
      });
      if (pushed.status !== 201) throw new Error(`par ${pushed.status}`);
      const { request_uri } = (await pushed.json()) as { request_uri: string };
      return { clientId, requestUri: request_uri, verifier: input.verifier };
    },
    { portal, challenge, verifier },
  );
}

/** The portal for one pushed grant, opened in its own tab with the fixture wallet. */
async function openGrant(pushed: PushedGrant) {
  const page = await browser.newPage();
  await page.setViewport({ width: 390, height: 844 });
  await installWallet(page);
  const query = new URLSearchParams({ client_id: pushed.clientId, request_uri: pushed.requestUri });
  await page.goto(`${portal}/authorize?${query}`);
  await page.waitForSelector("#signer-heading");
  return page;
}

/** Approves the reviewed grant, follows the callback, and redeems the code. */
async function approveAndRedeem(dappPage: Page, popup: Page, pushed: PushedGrant) {
  await popup.waitForSelector("::-p-text(Approve and sign):not([disabled])");
  await Promise.all([popup.waitForNavigation(), click(popup, "::-p-text(Approve and sign)")]);
  const code = new URL(popup.url()).searchParams.get("code");
  if (!code) throw new Error(`no code in ${popup.url()}`);
  return dappPage.evaluate(
    async (input) => {
      const response = await fetch(`${input.portal}/oauth/token`, {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: input.clientId,
          code: input.code,
          code_verifier: input.verifier,
          redirect_uri: `${location.origin}/callback`,
        }),
      });
      const token = (await response.json()) as {
        access_token: string;
        authorization_details: {
          grant_id: string;
          enable: { account: string; digest: `0x${string}`; enableSignature: `0x${string}` };
        }[];
      };
      const [grant] = token.authorization_details;
      if (!grant) throw new Error("no grant details");
      const read = await fetch(`${input.portal}/oauth/grants/${grant.grant_id}`, {
        headers: { authorization: `Bearer ${token.access_token}` },
      });
      return { status: response.status, grant, read: (await read.json()) as { status: string } };
    },
    { portal, clientId: pushed.clientId, verifier: pushed.verifier, code },
  );
}

describe("dapp grants approved by the account root against the real relay", () => {
  it("shows the wallet root the dapp's signer and policy, and its one signature approves it", async () => {
    const dappPage = await browser.newPage();
    await dappPage.goto(`${dapp}/`);
    const pushed = await pushGrant(dappPage);
    const popup = await openGrant(pushed);
    // The wallet signer and its account from the login proof are remembered.
    await click(popup, "::-p-text(E2E Wallet)");
    const account = await popup.waitForSelector("button[aria-label^='Smart account 0x']");
    const address = /0x[0-9a-f]{40}/u.exec(
      (await account?.evaluate((node) => node.getAttribute("aria-label"))) ?? "",
    )?.[0];
    await account?.click();
    await popup.waitForSelector(".review, [role=alert]");
    const review = await popup.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(review).toContain(`0x${"d1".repeat(20)}`);
    expect(review).toContain("transfer");
    expect(review).toContain(`0x${"aa".repeat(20)}`);
    expect(review).toContain("Up to 5 operations per chain every 1 day");
    expect(review).toContain("Arbitrum Sepolia");

    expect(walletSignatures).toBe(0);
    const redeemed = await approveAndRedeem(dappPage, popup, pushed);
    expect(walletSignatures).toBe(1);
    expect(redeemed.status).toBe(200);
    expect(redeemed.grant.enable.account).toBe(address);
    expect(
      (
        await recoverAddress({
          hash: redeemed.grant.enable.digest,
          signature: redeemed.grant.enable.enableSignature,
        })
      ).toLowerCase(),
    ).toBe(WALLET_ADDRESS);
    expect(redeemed.read.status).toBe("approved");
    await popup.close();
    await dappPage.close();
  });

  it("approves with a passkey root and refuses a signer that is not the account's root", async () => {
    const dappPage = await browser.newPage();
    await dappPage.goto(`${dapp}/`);
    const pushed = await pushGrant(dappPage);
    const popup = await openGrant(pushed);
    const session = await popup.createCDPSession();
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
    // The browser still holds the wallet signer's session from the previous test.
    const wallet = await popup.evaluate(async () => {
      const signers = JSON.parse(localStorage.getItem("oaath.portal.signers/v1") ?? "[]") as {
        signer_id: string;
        kind: string;
      }[];
      const signerId = signers.find((signer) => signer.kind === "wallet")?.signer_id;
      const owned = (await (await fetch(`/portal/signers/${signerId}/accounts`)).json()) as {
        accounts: { account_id: string }[];
      };
      return { signerId, accountId: owned.accounts[0]?.account_id };
    });
    expect(wallet.accountId).toBeDefined();
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer owns no account yet.)");

    // Signing the passkey in replaced the wallet's session: the wallet's accounts
    // are another signer's, and the passkey is not the wallet account's root.
    const refused = await popup.evaluate(
      async (input: { transactionId: string; walletId: string; accountId: string }) => {
        const signers = JSON.parse(localStorage.getItem("oaath.portal.signers/v1") ?? "[]") as {
          signer_id: string;
          kind: string;
        }[];
        const passkey = signers.find((signer) => signer.kind === "passkey");
        const listed = await fetch(`/portal/signers/${input.walletId}/accounts`);
        const prepared = await fetch(`/portal/transactions/${input.transactionId}/prepare`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ signer_id: passkey?.signer_id, account_id: input.accountId }),
        });
        return [listed.status, prepared.status];
      },
      {
        transactionId: pushed.requestUri.split(":").pop() ?? "",
        walletId: wallet.signerId ?? "",
        accountId: wallet.accountId ?? "",
      },
    );
    expect(refused).toEqual([403, 403]);

    await click(popup, "::-p-text(Create account)");
    const account = await popup.waitForSelector("button[aria-label^='Smart account 0x']");
    const address = /0x[0-9a-f]{40}/u.exec(
      (await account?.evaluate((node) => node.getAttribute("aria-label"))) ?? "",
    )?.[0];
    await account?.click();
    await popup.waitForSelector("#review-heading");
    const redeemed = await approveAndRedeem(dappPage, popup, pushed);
    expect(redeemed.status).toBe(200);
    expect(redeemed.grant.enable.account).toBe(address);
    expect(redeemed.read.status).toBe("approved");
    await popup.close();
    await dappPage.close();
  });
});

describe("dapp Grants requested with the SDK through the portal popup", () => {
  it("names the SDK's session key, the wallet root signs, and a reload resumes the Grant", async () => {
    const dappPage = await openDapp(grantDapp, "#grant:not([hidden])");
    const popup = await startLogin(dappPage, undefined, "#grant");
    await click(popup, "::-p-text(E2E Wallet)");
    const account = await popup.waitForSelector("button[aria-label^='Smart account 0x']");
    const address = /0x[0-9a-f]{40}/u.exec(
      (await account?.evaluate((node) => node.getAttribute("aria-label"))) ?? "",
    )?.[0];
    await account?.click();
    await popup.waitForSelector("::-p-text(Approve and sign):not([disabled])");
    const review = await popup.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(review).toContain(GRANT_TARGET);
    expect(review).toContain("Arbitrum Sepolia");
    const signatures = walletSignatures;
    await click(popup, "::-p-text(Approve and sign)");

    // The SDK verified the relay's request as its own and stored the Grant.
    expect(await outcome(dappPage.page)).toBe("granted");
    expect(walletSignatures).toBe(signatures + 1);
    const granted = await dappPage.page.evaluate(
      () =>
        (
          window as unknown as {
            oaathGrant: {
              state: string;
              binding: { context: { accountId: string }; operatorCredential: { address: string } };
            };
          }
        ).oaathGrant,
    );
    expect(granted.state).toBe("active");
    expect(granted.binding.context.accountId).toBe(address);
    // The portal reviewed exactly the SDK's own session key as the signer.
    expect(review).toContain(granted.binding.operatorCredential.address);

    // A reload resumes the same Grant from IndexedDB without the portal.
    await dappPage.page.reload();
    expect(await outcome(dappPage.page)).toBe("resumed");
    expect(
      await dappPage.page.evaluate(() => (window as unknown as { oaathGrant: unknown }).oaathGrant),
    ).toEqual(granted);
    await dappPage.page.close();
  });

  it("reports access_denied when the user cancels the Grant", async () => {
    const dappPage = await openDapp(grantDapp, "#grant:not([hidden])");
    const popup = await startLogin(dappPage, undefined, "#grant");
    await click(popup, "::-p-text(Cancel and return to the app)");
    expect(await outcome(dappPage.page)).toBe("oaath_client_access_denied");
    await dappPage.page.close();
  });
});

interface GrantDemo {
  readonly url: string;
  usage(): { used: number; maxRequests: number; stopped: string | null };
  close(): Promise<void>;
}
type StartGrantDemo = (input: Record<string, unknown>) => Promise<GrantDemo>;

/**
 * Local Arbitrum Sepolia: chain 421614 on Osaka Anvil with the pinned Kernel
 * stack and the ECDSA root validator, plus a minimal ERC-4337 facade that hands
 * each UserOperation to the EntryPoint. Reads, receipts and finality are
 * Anvil's own; only the bundler is a fixture.
 */
async function startLocalArbitrumSepolia() {
  const { startAnvil, deployKernelStack } = (await import(ANVIL)) as {
    startAnvil(
      chainId: number,
      hardfork: string,
    ): Promise<{
      url: string;
      client: {
        waitForTransactionReceipt(input: { hash: `0x${string}` }): Promise<{
          status: string;
          blockHash: `0x${string}`;
          blockNumber: bigint;
          logs: { topics: `0x${string}`[]; data: `0x${string}` }[];
        }>;
      };
      rpc(method: string, params?: unknown[]): Promise<unknown>;
      stop(): void;
    }>;
    deployKernelStack(chain: unknown): Promise<{
      submitter: { address: `0x${string}` };
      wallet: { sendTransaction(input: Record<string, unknown>): Promise<`0x${string}`> };
    }>;
  };
  const chain = await startAnvil(421_614, "osaka");
  closers.push(async () => chain.stop());
  const stack = await deployKernelStack(chain);
  const deployment = kernelDeployment({ chainId: 421_614 });
  const v33 = JSON.parse(await readFile(V33, "utf8")) as {
    ecdsaValidator: { deploymentInput: `0x${string}` };
  };
  const deployed = await stack.wallet.sendTransaction({
    to: deployment.create2Deployer,
    data: v33.ecdsaValidator.deploymentInput,
    gas: 10_000_000n,
  });
  await chain.client.waitForTransactionReceipt({ hash: deployed });

  const sent: UserOperation<"0.9">[] = [];
  const receipts = new Map<string, unknown>();
  const port = await listen(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += String(chunk);
    const rpc = JSON.parse(body) as { id: number; method: string; params: unknown[] };
    let result: unknown;
    if (rpc.method === "eth_chainId") result = toHex(421_614);
    else if (rpc.method === "eth_supportedEntryPoints") result = [deployment.entryPoint.address];
    else if (rpc.method === "eth_getUserOperationReceipt")
      result = receipts.get(String(rpc.params[0])) ?? null;
    else if (rpc.method === "eth_estimateUserOperationGas")
      result = {
        callGasLimit: "0xdbba0",
        verificationGasLimit: "0x2dc6c0",
        preVerificationGas: "0x249f0",
      };
    else if (rpc.method === "eth_sendUserOperation") {
      const wire = rpc.params[0] as Record<string, string>;
      const operation = {
        ...wire,
        nonce: BigInt(wire.nonce ?? "0"),
        callGasLimit: BigInt(wire.callGasLimit ?? "0"),
        verificationGasLimit: BigInt(wire.verificationGasLimit ?? "0"),
        preVerificationGas: BigInt(wire.preVerificationGas ?? "0"),
        maxFeePerGas: BigInt(wire.maxFeePerGas ?? "0"),
        maxPriorityFeePerGas: BigInt(wire.maxPriorityFeePerGas ?? "0"),
      } as unknown as UserOperation<"0.9">;
      sent.push(operation);
      const hash = getUserOperationHash({
        userOperation: operation,
        entryPointAddress: deployment.entryPoint.address,
        entryPointVersion: deployment.entryPoint.version,
        chainId: 421_614,
      });
      const transactionHash = await stack.wallet.sendTransaction({
        to: deployment.entryPoint.address,
        gas: 8_000_000n,
        data: encodeFunctionData({
          abi: entryPoint07Abi,
          functionName: "handleOps",
          args: [[toPackedUserOperation(operation)], stack.submitter.address],
        }),
      });
      const receipt = await chain.client.waitForTransactionReceipt({ hash: transactionHash });
      const event = receipt.logs
        .map((log) => {
          try {
            return decodeEventLog({
              abi: entryPoint07Abi,
              topics: log.topics as never,
              data: log.data,
            });
          } catch {
            return null;
          }
        })
        .find((entry) => entry?.eventName === "UserOperationEvent");
      if (!event || event.eventName !== "UserOperationEvent") throw new Error("no operation event");
      receipts.set(hash, {
        userOpHash: hash,
        entryPoint: deployment.entryPoint.address,
        sender: operation.sender,
        nonce: toHex(operation.nonce),
        actualGasCost: toHex(event.args.actualGasCost),
        actualGasUsed: toHex(event.args.actualGasUsed),
        success: event.args.success,
        receipt: {
          transactionHash,
          blockHash: receipt.blockHash,
          blockNumber: toHex(receipt.blockNumber),
        },
      });
      // A devnet finalizes as blocks arrive: two behind the head.
      await chain.rpc("anvil_mine", ["0x3"]);
      result = hash;
    } else throw new Error("ordinary RPC reached the bundler");
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
  });
  return { chain, sent, bundlerUrl: `http://127.0.0.1:${port}` };
}

describe("the live Grant demo, rehearsed on a local Arbitrum Sepolia", () => {
  it("grants, then one covered call deploys, enables and executes through the budgeted proxy", async () => {
    const local = await startLocalArbitrumSepolia();
    const { startGrantDemo } = (await import(GRANT_DEMO)) as { startGrantDemo: StartGrantDemo };
    const lines: string[] = [];
    const demo = await startGrantDemo({
      issuer: portal,
      chainId: 421_614,
      rpcUrl: local.chain.url,
      bundlerUrl: local.bundlerUrl,
      explorerTxUrl: "https://sepolia.arbiscan.io/tx/",
      maxRequests: 600,
      timeCapMs: 120_000,
      pollIntervalMs: 500,
      target: "0x000000000000000000000000000000000000dead",
      selector: "0x12345678",
      host: "127.0.0.1",
      log: (line: string) => lines.push(line),
    });
    closers.push(demo.close);

    const dappPage = await openDapp(demo.url, "#grant:not([disabled])");
    const popup = await startLogin(dappPage, undefined, "#grant");
    await signInWithRememberedWallet(popup);
    await popup.waitForSelector("::-p-text(Approve and sign):not([disabled])");
    const review = await popup.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(review).toContain("0x000000000000000000000000000000000000dead");
    const signatures = walletSignatures;
    await click(popup, "::-p-text(Approve and sign)");
    expect(await outcome(dappPage.page)).toBe("granted");
    expect(walletSignatures).toBe(signatures + 1);

    await dappPage.page.waitForSelector("#amount:not(:empty)");
    const account = await dappPage.page.$eval("#account", (node) => node.textContent ?? "");
    expect(account).toMatch(/^0x[0-9a-f]{40}$/u);
    expect(await dappPage.page.$eval("#amount", (node) => node.textContent)).toMatch(
      /^Send at least [0-9.]+ ETH on chain 421614/u,
    );
    expect(await local.chain.rpc("eth_getCode", [account, "latest"])).toBe("0x");
    await local.chain.rpc("anvil_setBalance", [account, toHex(10n ** 18n)]);
    await click(dappPage.page, "#balance");
    await dappPage.page.waitForSelector("::-p-text(1 ETH)");

    await click(dappPage.page, "#send");
    await dappPage.page.waitForSelector("#result[data-outcome=finalized]", { timeout: 30_000 });
    const operation = await dappPage.page.$eval("#operation", (node) => node.textContent ?? "");
    expect(operation).toMatch(/UserOperation 0x[0-9a-f]{64}/u);
    expect(operation).toMatch(/https:\/\/sepolia\.arbiscan\.io\/tx\/0x[0-9a-f]{64}/u);
    // One UserOperation: enable mode deployed the account and installed the permission.
    expect(local.sent).toHaveLength(1);
    expect(BigInt(local.sent[0]?.nonce ?? 0) >> 248n).toBe(12n);
    expect(local.sent[0]?.factory).toBeTruthy();
    expect(await local.chain.rpc("eth_getCode", [account, "latest"])).not.toBe("0x");
    // The root's one approval was the only signature; sending asked the wallet nothing.
    expect(walletSignatures).toBe(signatures + 1);

    // The proxy counted every request, and logs name methods, never endpoints.
    const usage = demo.usage();
    expect(usage.stopped).toBeNull();
    expect(usage.used).toBeGreaterThan(0);
    expect(usage.used).toBeLessThan(usage.maxRequests);
    expect(lines.join("\n")).not.toContain(local.chain.url);
    expect(lines.join("\n")).not.toContain(local.bundlerUrl);

    // A reload resumes the Grant and observes the stored operation; nothing is resent.
    await dappPage.page.reload();
    await dappPage.page.waitForSelector("#result[data-outcome=finalized]", { timeout: 30_000 });
    expect(local.sent).toHaveLength(1);
    await dappPage.page.close();
  });

  it("refuses to forward outside its method list, past its budget, or after its time cap", async () => {
    const local = await startLocalArbitrumSepolia();
    const { startGrantDemo } = (await import(GRANT_DEMO)) as { startGrantDemo: StartGrantDemo };
    const lines: string[] = [];
    const start = (input: Record<string, unknown>) =>
      startGrantDemo({
        issuer: portal,
        chainId: 421_614,
        rpcUrl: local.chain.url,
        bundlerUrl: local.bundlerUrl,
        target: "0x000000000000000000000000000000000000dead",
        selector: "0x12345678",
        host: "127.0.0.1",
        log: (line: string) => lines.push(line),
        maxRequests: 2,
        timeCapMs: 60_000,
        ...input,
      });
    const call = (demo: GrantDemo, method: string) =>
      fetch(`${demo.url}/rpc/chain`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] }),
      }).then(
        (response) => response.json() as Promise<{ result?: string; error?: { message: string } }>,
      );

    const budgeted = await start({});
    closers.push(budgeted.close);
    expect((await call(budgeted, "eth_sendRawTransaction")).error?.message).toBe(
      "method not allowed by the demo",
    );
    expect((await call(budgeted, "eth_chainId")).result).toBe(toHex(421_614));
    expect((await call(budgeted, "eth_chainId")).result).toBe(toHex(421_614));
    expect((await call(budgeted, "eth_chainId")).error?.message).toBe(
      "demo stopped: request budget exhausted",
    );
    // Once stopped, it stays stopped.
    expect(budgeted.usage()).toEqual({
      used: 2,
      maxRequests: 2,
      stopped: "request budget exhausted",
    });

    const capped = await start({ maxRequests: 100, timeCapMs: 1 });
    closers.push(capped.close);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect((await call(capped, "eth_chainId")).error?.message).toBe(
      "demo stopped: time cap reached",
    );
    expect(capped.usage().used).toBe(0);
  });
});

describe("adding a passkey on a second device to an existing account", () => {
  it("links, the wallet root approves with one signature, and the passkey logs in as the account", async () => {
    // The root device: its remembered wallet signer owns an account.
    const root = await browser.newPage();
    await root.setViewport({ width: 390, height: 844 });
    await installWallet(root);
    await root.goto(`${portal}/accounts`);
    await click(root, "::-p-text(E2E Wallet)");
    const owned = await root.waitForSelector("button[aria-label^='Smart account 0x']");
    const address = /0x[0-9a-f]{40}/u.exec(
      (await owned?.evaluate((node) => node.getAttribute("aria-label"))) ?? "",
    )?.[0];
    if (!address) throw new Error("no root account");

    // The second device: its own browser profile, a new passkey, no account.
    const device = await browser.createBrowserContext();
    const dappPage = await openDapp(dapp, "#login:not([disabled])", device);
    const popup = await startLogin(dappPage);
    const session = await popup.createCDPSession();
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
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");
    await click(popup, "::-p-text(Link to an existing account)");
    await popup.type("#link-account", address);
    await popup.$eval("#link-label", (node) => {
      (node as HTMLInputElement).select();
    });
    await popup.type("#link-label", "Second device");
    await click(popup, "::-p-text(Request access)");
    const shared = await popup.waitForSelector("#link-url");
    const linkUrl = (await shared?.evaluate((node) => node.textContent)) ?? "";
    expect(linkUrl).toMatch(new RegExp(`^${portal}/link/[A-Za-z0-9_-]+$`, "u"));
    expect(await popup.$("svg.qr")).not.toBeNull();

    // The root opens the link, signs in, reviews, and signs once.
    await root.goto(linkUrl);
    await click(root, "::-p-text(E2E Wallet)");
    await root.waitForSelector("::-p-text(Add a signer to your account)");
    const review = await root.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(review).toContain(address);
    expect(review).toContain("Passkey “Second device”");
    expect(review).toContain("Sign in only");
    const signatures = walletSignatures;
    await click(root, "::-p-text(Approve and sign)");
    await root.waitForSelector("::-p-text(Signer added)");
    expect(walletSignatures).toBe(signatures + 1);
    await root.waitForSelector("::-p-text(Second device)");

    // The second device sees the approval and signs in as the account.
    const linked = await popup.waitForSelector(
      `button[aria-label='Smart account ${address}, Signer']`,
    );
    await linked?.click();
    expect(await outcome(dappPage.page)).toBe("signed-in");
    const login: Record<string, unknown> = await dappPage.page.evaluate(() => {
      const value = (window as unknown as { oaathLogin: Record<string, unknown> }).oaathLogin;
      const clientKey = Object.keys(localStorage).find((key) =>
        key.startsWith("oaath-example-client:"),
      );
      return { ...value, clientId: clientKey ? localStorage.getItem(clientKey) : null };
    });
    const { payload } = await jwtVerify(
      String(login.idToken),
      createRemoteJWKSet(new URL(`${portal}/oauth/jwks`)),
      { issuer: portal, audience: String(login.clientId), algorithms: ["ES256"] },
    );
    expect(payload.sub).toBe(address);
    expect(payload.verified).toBe(true);
    expect(payload.signer).toMatchObject({ kind: "webauthn", profile: { kind: "webauthn" } });

    // The owner removes the member; nothing happens on-chain.
    await click(root, "button[aria-label='Remove Second device']");
    await click(root, "::-p-text(Confirm removal)");
    await root.waitForSelector("button[aria-label='Remove Second device']", { hidden: true });
    await root.close();
    await device.close();
  });
});
