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
import { calculateJwkThumbprint, createRemoteJWKSet, type JWK, jwtVerify } from "jose";
import puppeteer, { type Browser, type Page } from "puppeteer-core";
import { hashTypedData, recoverAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker, { type Env, ORIGIN } from "../worker/index.js";

const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const RELAY_DIR = fileURLToPath(new URL("../../relay", import.meta.url));
/** The fixture wallet's key: it signs only a grant's EIP-712 root approval. */
const WALLET = privateKeyToAccount(`0x${"5a".repeat(32)}`);
const WALLET_ADDRESS = WALLET.address.toLowerCase() as `0x${string}`;
/** Every signature the fixture wallet produced: logins ask for none. */
let walletSignatures = 0;
const EXAMPLE = fileURLToPath(new URL("../../examples/oauth-login/server.mjs", import.meta.url));

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
 * and eth_signTypedData_v4 with the fixture key; it records every method asked.
 */
async function installWallet(page: Page) {
  await page.exposeFunction("e2eWalletSignTypedData", (json: string) => {
    walletSignatures += 1;
    return WALLET.sign({ hash: hashTypedData(JSON.parse(json)) });
  });
  await page.evaluateOnNewDocument((address: string) => {
    const methods: string[] = [];
    Object.assign(window, { walletMethods: methods });
    const sign = (window as unknown as { e2eWalletSignTypedData(json: string): Promise<string> })
      .e2eWalletSignTypedData;
    const provider = {
      request: async ({ method, params }: { method: string; params?: [string, string] }) => {
        methods.push(method);
        if (method === "eth_requestAccounts") return [address];
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
async function openDapp(url = dapp, ready = "#login:not([disabled])") {
  const page = await browser.newPage();
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
    expect(
      await popup.evaluate(() => (window as unknown as { walletMethods: string[] }).walletMethods),
    ).toEqual(["eth_requestAccounts"]);
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
    expect(login.verified).toBe(false);
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
    expect(payload.verified).toBe(false);
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
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer owns no account yet.)");

    // The passkey is not the wallet account's root: the relay refuses to prepare.
    const refused = await popup.evaluate(async (transactionId: string) => {
      const signers = JSON.parse(localStorage.getItem("oaath.portal.signers/v1") ?? "[]") as {
        signer_id: string;
        kind: string;
      }[];
      const passkey = signers.find((signer) => signer.kind === "passkey");
      const wallet = signers.find((signer) => signer.kind === "wallet");
      const owned = (await (
        await fetch(`/portal/signers/${wallet?.signer_id}/accounts`)
      ).json()) as { accounts: { account_id: string }[] };
      const response = await fetch(`/portal/transactions/${transactionId}/prepare`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          signer_id: passkey?.signer_id,
          account_id: owned.accounts[0]?.account_id,
        }),
      });
      return response.status;
    }, pushed.requestUri.split(":").pop() ?? "");
    expect(refused).toBe(403);

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
