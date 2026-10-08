/**
 * Login with OAAth end to end, with no stub on the authorization path:
 *
 * - the real Rust relay binary, configured as production runs it (kid from
 *   the key thumbprint) with the memory store and a throwaway ES256 key;
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
import { p256 } from "@noble/curves/nist.js";
import {
  encodeKernelPermissionUninstallCalls,
  hashOwnerCredentialProfile,
  OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
  parseOwnerOperationRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { deriveSessionPolicyProfiles } from "@oaath/sdk/advanced";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
import {
  createKernelRuntime,
  ECDSA_VALIDATOR,
  kernelDeployment,
  kernelKey,
  materializeKernelPermission,
  ownerOperator,
  prepareDerivedAccountPermissionApproval,
  prepareKernelPermissionApproval,
  prepareOwnerOperation,
  sessionOperator,
  verifyOwnerOperation,
} from "@oaath/sdk/kernel";
import { calculateJwkThumbprint, createRemoteJWKSet, type JWK, jwtVerify } from "jose";
import puppeteer, { type Browser, type Page, type Protocol } from "puppeteer-core";
import {
  decodeEventLog,
  encodeAbiParameters,
  encodeFunctionData,
  hashTypedData,
  keccak256,
  parseAbi,
  recoverAddress,
  toHex,
} from "viem";
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
  // The relay proves an import's root on chain through this loopback hop to
  // whichever local chain a test started; nothing reaches a public RPC.
  const rpcPort = await listen(async (incoming, outgoing) => {
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) chunks.push(chunk as Buffer);
    try {
      const upstream = await fetch(rpcUpstream, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: Buffer.concat(chunks),
      });
      outgoing.writeHead(upstream.status, { "content-type": "application/json" });
      outgoing.end(Buffer.from(await upstream.arrayBuffer()));
    } catch {
      outgoing.writeHead(502).end();
    }
  });
  // Revocations go through this loopback hop to whichever local bundler a test started.
  const bundlerPort = await listen(async (incoming, outgoing) => {
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) chunks.push(chunk as Buffer);
    try {
      const upstream = await fetch(bundlerUpstream, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: Buffer.concat(chunks),
      });
      outgoing.writeHead(upstream.status, { "content-type": "application/json" });
      outgoing.end(Buffer.from(await upstream.arrayBuffer()));
    } catch {
      outgoing.writeHead(502).end();
    }
  });
  relay = spawn(join(RELAY_DIR, "target/debug/oaath-relay"), [], {
    stdio: ["ignore", "ignore", "inherit"],
    env: {
      PATH: process.env.PATH ?? "",
      RUST_LOG: "warn",
      OAATH_LISTEN: `127.0.0.1:${port}`,
      OAATH_KMS_KEY: randomBytes(32).toString("hex"),
      OAATH_ISSUER: issuer,
      OAATH_ID_TOKEN_KEY: join(work, "id-token.pem"),
      OAATH_RPC_421614: `http://127.0.0.1:${rpcPort}/`,
      OAATH_BUNDLER_421614: `http://127.0.0.1:${bundlerPort}/`,
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

/**
 * The Worker's chain-read provider: a closed loopback port until a test starts
 * its local Arbitrum Sepolia, so no test can reach a public endpoint.
 */
let rpcUpstream = "http://127.0.0.1:9/";
/** The relay's bundler: closed until a test starts its local bundler. */
let bundlerUpstream = "http://127.0.0.1:9/";

/** The portal origin: Node's HTTP server in front of the real Worker module. */
async function startPortal() {
  const env: Env = {
    get RPC_UPSTREAM_421614() {
      return rpcUpstream;
    },
    RPC_LIMIT: { limit: async () => ({ success: true }) },
    WRITE_LIMIT: { limit: async () => ({ success: true }) },
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
          version: "oaath.grant-policy/v1",
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
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");

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
    else if (rpc.method === "pimlico_getUserOperationGasPrice") {
      const price = { maxFeePerGas: "0x77359400", maxPriorityFeePerGas: "0x3b9aca00" };
      result = { slow: price, standard: price, fast: price };
    } else if (rpc.method === "eth_estimateUserOperationGas")
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
  return { chain, stack, sent, bundlerUrl: `http://127.0.0.1:${port}` };
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

/** A CDP virtual authenticator in `page`: user present and verified. */
async function addAuthenticator(page: Page) {
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
  return { session, id: authenticatorId };
}

/** The device's existing passkey, in a new popup's authenticator. */
async function withCredential(page: Page, credentials: readonly Protocol.WebAuthn.Credential[]) {
  const authenticator = await addAuthenticator(page);
  for (const credential of credentials)
    await authenticator.session.send("WebAuthn.addCredential", {
      authenticatorId: authenticator.id,
      credential,
    });
}

describe("adding a passkey on a second device to an existing account", () => {
  it("links, the root approves, the passkey logs in, and suspension refuses it until restored", async () => {
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
    const authenticator = await addAuthenticator(popup);
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");
    // The device keeps its passkey; each later popup gets the same credential.
    const { credentials } = await authenticator.session.send("WebAuthn.getCredentials", {
      authenticatorId: authenticator.id,
    });
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
    await root.waitForSelector("button[aria-label='Suspend Second device']");

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
    expect(payload.oaath_accounts).toEqual([{ address, role: "permission", status: "active" }]);
    expect(login.accounts).toEqual(payload.oaath_accounts);

    // The owner suspends the member: its next login is refused.
    await click(root, "button[aria-label='Suspend Second device']");
    await click(root, "::-p-text(Confirm suspension)");
    await root.waitForSelector("::-p-text(Suspended)");
    const again = await openDapp(dapp, "#login:not([disabled])", device);
    let retry = await startLogin(again);
    await withCredential(retry, credentials);
    await click(retry, "::-p-text(Passkey)");
    const suspended = await retry.waitForSelector(
      `button[aria-label='Smart account ${address}, Signer, suspended']`,
    );
    expect(await suspended?.evaluate((node) => (node as HTMLButtonElement).disabled)).toBe(true);
    // The relay refuses the decision itself, not only the screen.
    const refused = await retry.evaluate(async (account: string) => {
      const transaction = new URLSearchParams(location.search).get("request_uri")?.split(":").pop();
      const [signer] = JSON.parse(localStorage.getItem("oaath.portal.signers/v1") ?? "[]") as {
        signer_id: string;
      }[];
      const { accounts } = (await (
        await fetch(`/portal/signers/${signer?.signer_id}/accounts`)
      ).json()) as { accounts: { account_id: string; address: string }[] };
      const response = await fetch(`/portal/transactions/${transaction}/decision`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          outcome: "approved",
          signer_id: signer?.signer_id,
          account_id: accounts.find((entry) => entry.address === account)?.account_id,
        }),
      });
      return { status: response.status, body: await response.json() };
    }, address);
    expect(refused).toEqual({
      status: 403,
      body: { error: { code: "relay_membership_suspended" } },
    });
    await click(retry, "::-p-text(Cancel and return to the app)");
    expect(await outcome(again.page)).toBe("oaath_client_access_denied");

    // Restored, the member logs in again.
    await click(root, "button[aria-label='Restore Second device']");
    await click(root, "::-p-text(Confirm restore)");
    await root.waitForSelector("button[aria-label='Suspend Second device']");
    retry = await startLogin(again);
    await withCredential(retry, credentials);
    await click(retry, "::-p-text(Passkey)");
    await click(retry, `button[aria-label='Smart account ${address}, Signer']`);
    // The page still shows the cancelled attempt until this login lands.
    await again.page.waitForSelector("#result[data-outcome='signed-in']");
    await again.page.close();

    // The owner removes the member; nothing happens on-chain.
    await click(root, "button[aria-label='Remove Second device']");
    await click(root, "::-p-text(Confirm removal)");
    await root.waitForSelector("button[aria-label='Remove Second device']", { hidden: true });
    await root.close();
    await device.close();
  });

  it("links with a policy template: the root's one signature is the member's enable", async () => {
    // The owner keeps a template for the account.
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
    await owned?.click();
    // The policies section renders once its templates load; locators retry.
    await root.locator("button::-p-text(New policy)").click();
    await root.type("#policy-name", "Payments");
    await root.type(".policy-target", `0x${"ab".repeat(20)}`);
    await click(root, "::-p-text(Save policy)");
    await root.waitForSelector("button[aria-label='Edit Payments']");
    expect(
      await root.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);

    // A new passkey on another device asks to join.
    const device = await browser.createBrowserContext();
    const dappPage = await openDapp(dapp, "#login:not([disabled])", device);
    const popup = await startLogin(dappPage);
    await addAuthenticator(popup);
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");
    await click(popup, "::-p-text(Link to an existing account)");
    await popup.type("#link-account", address);
    await click(popup, "::-p-text(Request access)");
    const shared = await popup.waitForSelector("#link-url");
    const linkUrl = (await shared?.evaluate((node) => node.textContent)) ?? "";
    const linkId = linkUrl.split("/").pop() ?? "";

    // The owner gives it the template and signs the member's enable once.
    await root.goto(linkUrl);
    await click(root, "::-p-text(E2E Wallet)");
    await click(root, "::-p-text(spend within “Payments”)");
    const signatures = walletSignatures;
    await click(root, "::-p-text(Approve and sign)");
    await root.waitForSelector("::-p-text(Signer added)");
    expect(walletSignatures).toBe(signatures + 1);
    await root.waitForSelector("::-p-text(1 policy)");

    // The member signs in as the account, and reads its approved grant.
    await click(popup, `button[aria-label='Smart account ${address}, Signer']`);
    expect(await outcome(dappPage.page)).toBe("signed-in");
    const reader = await device.newPage();
    await reader.goto(`${portal}/`);
    const grant = await reader.evaluate(async (id: string) => {
      const response = await fetch(`/portal/grants/${id}`);
      return (await response.json()) as {
        status: string;
        permission_request: {
          operatorCredential: { kind: string };
          application: { clientId: string };
        };
        enable: { account: string };
      };
    }, linkId);
    expect(grant.status).toBe("approved");
    expect(grant.permission_request.operatorCredential.kind).toBe("webauthn");
    expect(grant.permission_request.application.clientId).toBe("oaath-portal");
    expect(grant.enable.account).toBe(address);
    await root.close();
    await device.close();
  });
});

/** The dapp's raw token request for one pushed grant's code. */
async function redeem(dappPage: Page, pushed: PushedGrant, code: string) {
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
      return {
        status: response.status,
        body: (await response.json()) as {
          error?: string;
          authorization_details?: { grant_id: string; enable: { account: string } }[];
        },
      };
    },
    { portal, clientId: pushed.clientId, verifier: pushed.verifier, code },
  );
}

describe("a member's grant request waits for the account root", () => {
  it("the member asks, the token is pending, the root approves in /accounts, the dapp redeems", async () => {
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

    // A member device: a new passkey linked to the root's account, sign-in only.
    const device = await browser.createBrowserContext();
    const dappPage = await device.newPage();
    await dappPage.goto(`${dapp}/`);
    const pushed = await pushGrant(dappPage);
    const popup = await device.newPage();
    await popup.setViewport({ width: 390, height: 844 });
    const query = new URLSearchParams({
      client_id: pushed.clientId,
      request_uri: pushed.requestUri,
    });
    await popup.goto(`${portal}/authorize?${query}`);
    await addAuthenticator(popup);
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");
    await click(popup, "::-p-text(Link to an existing account)");
    await popup.type("#link-account", address);
    await click(popup, "::-p-text(Request access)");
    const shared = await popup.waitForSelector("#link-url");
    await root.goto((await shared?.evaluate((node) => node.textContent)) ?? "");
    await click(root, "::-p-text(E2E Wallet)");
    await click(root, "::-p-text(Approve and sign)");
    await root.waitForSelector("::-p-text(Signer added)");

    // The member picks the account and sends the request; the dapp gets a code at once.
    await click(popup, `button[aria-label='Smart account ${address}, Signer']`);
    await popup.waitForSelector("#ask-heading");
    const ask = await popup.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(ask).toContain(`0x${"d1".repeat(20)}`);
    const requestId = pushed.requestUri.split(":").pop() ?? "";
    expect(ask).toContain(`${portal}/requests/${requestId}`);
    await Promise.all([
      popup.waitForNavigation(),
      click(popup, "::-p-text(Send request to the owner)"),
    ]);
    const callback = new URL(popup.url());
    expect(callback.searchParams.get("state")).toBe("grant-state");
    const code = callback.searchParams.get("code");
    if (!code) throw new Error(`no code in ${popup.url()}`);
    expect(await redeem(dappPage, pushed, code)).toMatchObject({
      status: 400,
      body: { error: "authorization_pending" },
    });

    // The root approves from its members view with one signature.
    await root.goto(`${portal}/accounts`);
    await click(root, "::-p-text(E2E Wallet)");
    await click(root, `button[aria-label='Smart account ${address}']`);
    await root.waitForSelector("#requests-heading");
    const queue = await root.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(queue).toContain("E2E Grant Dapp");
    expect(queue).toContain(`0x${"d1".repeat(20)}`);
    const signatures = walletSignatures;
    await click(root, "button[aria-label='Approve E2E Grant Dapp']");
    await root.waitForSelector("#requests-heading", { hidden: true });
    expect(walletSignatures).toBe(signatures + 1);

    const redeemed = await redeem(dappPage, pushed, code);
    expect(redeemed.status).toBe(200);
    expect(redeemed.body.authorization_details?.[0]?.grant_id).toBe(requestId);
    expect(redeemed.body.authorization_details?.[0]?.enable.account).toBe(address);
    expect(await redeem(dappPage, pushed, code)).toMatchObject({
      status: 400,
      body: { error: "invalid_grant" },
    });
    await root.close();
    await device.close();
  });
});

describe("a member's Grant requested with the SDK waits for the root, then installs on chain", () => {
  it("returns pending, the root approves in /accounts, redeemPending after a reload yields the Grant, and the first operation enables it", async () => {
    const local = await startLocalArbitrumSepolia();
    const { startGrantDemo } = (await import(GRANT_DEMO)) as { startGrantDemo: StartGrantDemo };
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
      log: () => undefined,
    });
    closers.push(demo.close);

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

    // A member device: the SDK's popup, a new passkey linked to the root's account.
    const device = await browser.createBrowserContext();
    const dappPage = await openDapp(demo.url, "#grant:not([disabled])", device);
    const popup = await startLogin(dappPage, undefined, "#grant");
    await addAuthenticator(popup);
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");
    await click(popup, "::-p-text(Link to an existing account)");
    await popup.type("#link-account", address);
    await click(popup, "::-p-text(Request access)");
    const shared = await popup.waitForSelector("#link-url");
    await root.goto((await shared?.evaluate((node) => node.textContent)) ?? "");
    await click(root, "::-p-text(E2E Wallet)");
    await click(root, "::-p-text(Approve and sign)");
    await root.waitForSelector("::-p-text(Signer added)");

    // The member sends the request: the SDK journals the code and reports pending.
    await click(popup, `button[aria-label='Smart account ${address}, Signer']`);
    await popup.waitForSelector("#ask-heading");
    await click(popup, "::-p-text(Send request to the owner)");
    expect(await outcome(dappPage.page)).toBe("pending");
    expect(await dappPage.page.$eval("#account", (node) => node.textContent)).toBe("");

    // The root approves from its members view with one signature.
    await root.goto(`${portal}/accounts`);
    await click(root, "::-p-text(E2E Wallet)");
    await click(root, `button[aria-label='Smart account ${address}']`);
    await root.waitForSelector("#requests-heading");
    const signatures = walletSignatures;
    await click(root, "button[aria-label='Approve OAAth Grant demo']");
    await root.waitForSelector("#requests-heading", { hidden: true });
    expect(walletSignatures).toBe(signatures + 1);
    await root.close();

    // A reload recreates the SDK; redeemPending exchanges the journaled code once.
    await dappPage.page.reload();
    expect(await outcome(dappPage.page)).toBe("granted");
    await dappPage.page.waitForSelector("#amount:not(:empty)");
    expect(await dappPage.page.$eval("#account", (node) => node.textContent)).toBe(address);

    // The first covered call deploys the account and enables the member's permission.
    expect(await local.chain.rpc("eth_getCode", [address, "latest"])).toBe("0x");
    await local.chain.rpc("anvil_setBalance", [address, toHex(10n ** 18n)]);
    await click(dappPage.page, "#send");
    await dappPage.page.waitForSelector("#result[data-outcome=finalized]", { timeout: 30_000 });
    expect(local.sent).toHaveLength(1);
    expect(BigInt(local.sent[0]?.nonce ?? 0) >> 248n).toBe(12n);
    expect(local.sent[0]?.factory).toBeTruthy();
    expect(await local.chain.rpc("eth_getCode", [address, "latest"])).not.toBe("0x");
    // Approval was the root's one signature; the member's send asked it nothing.
    expect(walletSignatures).toBe(signatures + 1);
    await device.close();
  });
});

/** One JSON call straight to the relay, with an optional session cookie. */
async function relayCall(path: string, cookie?: string, body?: unknown, method?: "DELETE") {
  const response = await fetch(`${relayBase}${path}`, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(cookie ? { cookie } : {}),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const json = (await response.json()) as Record<string, unknown>;
  if (!response.ok) throw new Error(`${path}: ${response.status} ${JSON.stringify(json)}`);
  return { json, cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "" };
}

/** Registers a signer and signs it in with `prove(challenge)`; answers its id and cookie. */
async function relaySignIn(
  profile: unknown,
  prove: (challenge: { nonce: string; message?: string }) => Promise<string>,
) {
  const signerId = String(
    (await relayCall("/portal/signers", undefined, { profile })).json.signer_id,
  );
  const challenge = (
    await relayCall("/portal/sessions/challenge", undefined, { signer_id: signerId })
  ).json as { nonce: string; message?: string };
  const { cookie } = await relayCall("/portal/sessions", undefined, {
    signer_id: signerId,
    nonce: challenge.nonce,
    signature: await prove(challenge),
  });
  return { signerId, cookie };
}

/**
 * A software passkey: user present and verified, fixed counter, bound to the
 * issuer's relying party so the relay admits its sign-in. Kernel's WebAuthn
 * signer checks the challenge and the P-256 signature, not the RP ID.
 */
function softwarePasskey() {
  const secret = p256.utils.randomPrivateKey();
  const rawId = randomBytes(16);
  const credential = {
    version: "oaath.owner-credential-profile/v1",
    kind: "webauthn",
    publicKey: toHex(p256.getPublicKey(secret, false)),
    authenticatorIdHash: keccak256(rawId),
  } as const;
  const rpId = new URL(portal).hostname;
  const rpIdHash = createHash("sha256").update(rpId).digest("hex");
  const key = kernelKey({
    kind: "webauthn",
    credential,
    credentialId: rawId.toString("base64url"),
    rpId,
    origin: portal,
    authenticate: async (request) => {
      const clientDataJSON = JSON.stringify({
        type: "webauthn.get",
        challenge: request.challenge,
        origin: portal,
        crossOrigin: false,
      });
      const authenticatorData = `0x${rpIdHash}0500000001` as const;
      const message = createHash("sha256")
        .update(Buffer.from(authenticatorData.slice(2), "hex"))
        .update(createHash("sha256").update(clientDataJSON).digest())
        .digest();
      const signature = p256.sign(message, secret, { lowS: true, prehash: false });
      return {
        authenticatorData,
        clientDataJSON,
        responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
        r: toHex(signature.r, { size: 32 }),
        s: toHex(signature.s, { size: 32 }),
      };
    },
  });
  return { credential, key };
}

/** Submits one signed operation through the EntryPoint; answers its event's success, or null. */
async function handleOperation(
  local: Awaited<ReturnType<typeof startLocalArbitrumSepolia>>,
  prepared: {
    readonly userOperation: {
      sender: `0x${string}`;
      nonce: string;
      callData: `0x${string}`;
      callGasLimit: string;
      verificationGasLimit: string;
      preVerificationGas: string;
      maxFeePerGas: string;
      maxPriorityFeePerGas: string;
      factory: { address: `0x${string}`; data: `0x${string}` } | null;
    };
  },
  signature: `0x${string}`,
): Promise<boolean | null> {
  const operation = prepared.userOperation;
  const hash = await local.stack.wallet.sendTransaction({
    to: kernelDeployment({ chainId: 421_614 }).entryPoint.address,
    gas: 8_000_000n,
    data: encodeFunctionData({
      abi: entryPoint07Abi,
      functionName: "handleOps",
      args: [
        [
          toPackedUserOperation({
            sender: operation.sender,
            nonce: BigInt(operation.nonce),
            callData: operation.callData,
            callGasLimit: BigInt(operation.callGasLimit),
            verificationGasLimit: BigInt(operation.verificationGasLimit),
            preVerificationGas: BigInt(operation.preVerificationGas),
            maxFeePerGas: BigInt(operation.maxFeePerGas),
            maxPriorityFeePerGas: BigInt(operation.maxPriorityFeePerGas),
            ...(operation.factory
              ? { factory: operation.factory.address, factoryData: operation.factory.data }
              : {}),
            signature,
          }),
        ],
        local.stack.submitter.address,
      ],
    }),
  });
  const receipt = await local.chain.client.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") return null;
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
  return event?.eventName === "UserOperationEvent" ? event.args.success : null;
}

/**
 * Through the real relay: a root's account (derived, or deployed outside
 * OAAth and imported), a policy template, and a software-passkey member the
 * root grants it; the member's first covered call enables and executes.
 */
async function memberGrantOnChain(kind: "derived" | "imported") {
  const local = await startLocalArbitrumSepolia();
  rpcUpstream = local.chain.url;
  const deployment = kernelDeployment({ chainId: 421_614 });
  const [ports] = createCetaneChainPorts({ 421614: { publicRpcUrls: [local.chain.url] } });
  if (!ports) throw new Error("no chain reads");
  const reads = ports.reads;

  // The root: an ECDSA key that signs in with SIWE and owns one account.
  const rootAccount = privateKeyToAccount(`0x${randomBytes(32).toString("hex")}`);
  const rootProfile = {
    version: "oaath.owner-credential-profile/v1",
    kind: "ecdsa",
    address: rootAccount.address.toLowerCase() as `0x${string}`,
  } as const;
  const rootKey = kernelKey({
    account: { address: rootProfile.address, sign: ({ hash }) => rootAccount.sign({ hash }) },
    validator: ECDSA_VALIDATOR,
  });
  const root = await relaySignIn(rootProfile, async (challenge) =>
    rootAccount.signMessage({ message: challenge.message ?? "" }),
  );
  const owner = createKernelRuntime({
    deployment,
    operator: ownerOperator({
      key: kernelKey({ credential: rootProfile, validator: ECDSA_VALIDATOR }),
    }),
    reads,
  });
  let account: { account_id: string; address: `0x${string}` };
  if (kind === "derived") {
    account = (
      await relayCall("/portal/accounts", root.cookie, {
        root_signer_id: root.signerId,
        creation_key: randomBytes(16).toString("hex"),
      })
    ).json as typeof account;
  } else {
    // An account deployed outside OAAth, then imported with the root's statement.
    const existing = await owner.bindAccount({
      accountIndex: "90",
      initialPackages: owner.packages,
    });
    if (existing.state !== "counterfactual" || !("factoryDeployCalldata" in existing))
      throw new Error("account already deployed");
    const hash = await local.stack.wallet.sendTransaction({
      to: existing.factory,
      data: existing.factoryDeployCalldata,
      gas: 3_000_000n,
    });
    await local.chain.client.waitForTransactionReceipt({ hash });
    const address = existing.account.toLowerCase() as `0x${string}`;
    const issuedAt = Math.floor(Date.now() / 1000) - 5;
    const fingerprint = `0x${"33".repeat(32)}` as const;
    const signature = await rootAccount.sign({
      hash: hashTypedData({
        domain: { name: "OAAth", version: "1" },
        types: {
          AccountImport: [
            { name: "account", type: "address" },
            { name: "ownerProfileHash", type: "bytes32" },
            { name: "inventoryFingerprint", type: "bytes32" },
            { name: "issuedAt", type: "uint64" },
            { name: "nonce", type: "string" },
          ],
        },
        primaryType: "AccountImport",
        message: {
          account: address,
          ownerProfileHash: hashOwnerCredentialProfile(rootProfile),
          inventoryFingerprint: fingerprint,
          issuedAt: BigInt(issuedAt),
          nonce: "member-grant-1",
        },
      }),
    });
    account = (
      await relayCall("/portal/accounts/import", root.cookie, {
        root_signer_id: root.signerId,
        address,
        inventory_fingerprint: fingerprint,
        issued_at: issuedAt,
        nonce: "member-grant-1",
        signature,
      })
    ).json as typeof account;
  }
  const target = `0x${"7c".repeat(20)}` as const;
  const template = (
    await relayCall(`/portal/accounts/${account.account_id}/policies`, root.cookie, {
      name: "Member payments",
      lifetime_seconds: 3_600,
      policy: {
        calls: [{ target, selector: "0x12345678", valueLimit: "500" }],
        perChainOperationLimit: { count: 3, intervalSeconds: null },
      },
    })
  ).json as { template_id: string };

  // The member: a passkey that asks to join, and the root grants it the template.
  const passkey = softwarePasskey();
  const member = await relaySignIn(passkey.credential, async (challenge) =>
    passkey.key.sign(`0x${challenge.nonce}`),
  );
  const linkId = String(
    (
      await relayCall("/portal/links", member.cookie, {
        signer_id: member.signerId,
        account: account.address,
        label: "Laptop",
      })
    ).json.link_id,
  );
  const prepared = (
    await relayCall(`/portal/links/${linkId}/prepare`, root.cookie, {
      template_id: template.template_id,
    })
  ).json as {
    permission_request: unknown;
    signing_request: { expectedDigest: `0x${string}` };
  };
  const request = parsePermissionRequest(prepared.permission_request);
  expect(request.operatorCredential).toMatchObject({
    kind: "webauthn",
    publicKey: passkey.credential.publicKey,
  });
  // The root signs only the install the SDK derives itself.
  const approval =
    kind === "derived"
      ? prepareDerivedAccountPermissionApproval({
          request,
          chainId: 421_614,
          account: account.address,
        })
      : await prepareKernelPermissionApproval({ request, chainId: 421_614, reads });
  expect(approval.signingRequest.expectedDigest).toBe(prepared.signing_request.expectedDigest);
  const decision = await approval.sign(rootKey, Math.floor(Date.now() / 1000));
  await relayCall(`/portal/links/${linkId}/approve`, root.cookie, {
    template_id: template.template_id,
    artifact: JSON.stringify(decision),
  });

  // The member reads its grant and spends it: the first covered call
  // installs the permission in enable mode and executes.
  const grant = (await relayCall(`/portal/grants/${linkId}`, member.cookie)).json as {
    status: string;
    permission_request: unknown;
    enable: Parameters<typeof materializeKernelPermission>[0]["approval"];
  };
  expect(grant.status).toBe("approved");
  expect(grant.enable.account).toBe(account.address);
  const granted = parsePermissionRequest(grant.permission_request);
  const session = createKernelRuntime({
    deployment,
    operator: sessionOperator({
      key: passkey.key,
      policies: deriveSessionPolicyProfiles(granted.policy),
    }),
    reads,
  });
  const profile = granted.logicalAccount;
  const bound =
    "accountIndex" in profile
      ? await session.bindAccount({
          accountIndex: profile.accountIndex,
          initialPackages: owner.packages,
        })
      : await session.bindAccount({ address: account.address });
  expect("accountIndex" in profile).toBe(kind === "derived");
  await local.chain.rpc("anvil_setBalance", [account.address, toHex(10n ** 18n)]);
  const first = await materializeKernelPermission({
    approval: grant.enable,
    runtime: session,
    grantId: linkId,
    account: bound,
    nonceKey: "0",
    sequence: "0",
    calls: [{ target, value: "500", data: "0x12345678" }],
    gas: {
      callGasLimit: "900000",
      verificationGasLimit: "3000000",
      preVerificationGas: "150000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
    },
  });
  expect(first.prepared.userOperation.factory === null).toBe(kind === "imported");
  expect(await handleOperation(local, first.prepared, first.signature)).toBe(true);
  expect(await local.chain.rpc("eth_getBalance", [target, "latest"])).toBe("0x1f4");
  return {
    local,
    reads,
    rootAccount,
    rootProfile,
    root,
    owner,
    account,
    member,
    linkId,
    session,
    target,
  };
}

describe("a template-granted passkey member's first operation on chain", () => {
  it.each(["derived", "imported"] as const)(
    "%s account: the root's one signature through the relay, then the member's first call enables and executes",
    async (kind) => {
      await memberGrantOnChain(kind);
    },
    120_000,
  );
});

/** Whether `account` still has the grant's permission installed, from its install packages. */
async function permissionInstalled(
  local: Awaited<ReturnType<typeof startLocalArbitrumSepolia>>,
  account: `0x${string}`,
  packages: readonly { moduleType: number; module: `0x${string}`; moduleData: `0x${string}` }[],
) {
  const signer = packages.find((entry) => entry.moduleType === 6);
  if (!signer) throw new Error("no signer package");
  const answer = await local.chain.rpc("eth_call", [
    {
      to: account,
      data: encodeFunctionData({
        abi: parseAbi([
          "function isModuleInstalled(uint256 moduleType, address module, bytes context) view returns (bool)",
        ]),
        functionName: "isModuleInstalled",
        args: [6n, signer.module, signer.moduleData.slice(0, 10) as `0x${string}`],
      }),
    },
    "latest",
  ]);
  return BigInt(answer as string) === 1n;
}

interface Revocation {
  status: string;
  delivery: string;
  packages: { moduleType: number; module: `0x${string}`; moduleData: `0x${string}` }[];
  request: {
    calls: unknown;
    userOperationHash: `0x${string}`;
    userOperation: Record<string, unknown>;
  } | null;
}

/** The root prepares and signs the grant's uninstall through the relay; answers the signed view. */
async function rootRevokes(
  grantId: string,
  rootCookie: string,
  rootProfile: {
    readonly version: "oaath.owner-credential-profile/v1";
    readonly kind: "ecdsa";
    readonly address: `0x${string}`;
  },
  rootAccount: ReturnType<typeof privateKeyToAccount>,
  address: `0x${string}`,
) {
  const path = `/portal/grants/${grantId}/revocation`;
  expect(((await relayCall(path, rootCookie)).json as unknown as Revocation).status).toBe(
    "pending_signature",
  );
  const prepared = (
    await relayCall(`${path}/prepare`, rootCookie, {
      estimation_signature: kernelKey({ credential: rootProfile, validator: ECDSA_VALIDATOR })
        .dummySignature,
    })
  ).json as unknown as Revocation;
  if (!prepared.request) throw new Error("no prepared revocation");
  // The relay's calls are exactly the protocol's uninstall of this grant's packages.
  const request = parseOwnerOperationRequest(prepared.request);
  expect(request.calls).toEqual(
    encodeKernelPermissionUninstallCalls({
      account: address,
      packages: prepared.packages as never,
    }),
  );
  expect(request.userOperation.sender).toBe(address);
  const signature = await rootAccount.signMessage({ message: { raw: request.userOperationHash } });
  const signed = (await relayCall(`${path}/sign`, rootCookie, { signature }))
    .json as unknown as Revocation;
  return { prepared, signed, request };
}

/** Polls the root's status, mining blocks, until it is finalized. */
async function finalized(
  local: Awaited<ReturnType<typeof startLocalArbitrumSepolia>>,
  grantId: string,
  rootCookie: string,
) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const view = (await relayCall(`/portal/grants/${grantId}/revocation`, rootCookie))
      .json as unknown as Revocation;
    if (view.status === "finalized" || view.status === "failed") return view.status;
    await local.chain.rpc("anvil_mine", ["0x40"]);
  }
  return "unfinished";
}

describe("revoking an invalidated grant on chain", () => {
  it("removes a member: the root signs the uninstall once, the relay submits it, and the member's next call fails", async () => {
    const context = await memberGrantOnChain("derived");
    const { local, session, linkId, target } = context;
    bundlerUpstream = local.bundlerUrl;
    const address = context.account.address;
    const gas = {
      callGasLimit: "900000",
      verificationGasLimit: "3000000",
      preVerificationGas: "150000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
    };
    const deployed = await session.bindAccount({
      accountIndex: "0",
      initialPackages: context.owner.packages,
    });
    const next = async (sequence: string) => {
      const prepared = session.prepareOperation({
        kind: "execution",
        grantId: linkId,
        account: deployed,
        nonceKey: "0",
        sequence,
        calls: [{ target, value: "500", data: "0x12345678" }],
        gas,
      });
      return handleOperation(local, prepared, await session.signOperation(prepared));
    };
    // Installed: the member's second call runs in standard mode.
    expect(await next("0")).toBe(true);

    // The root removes the member: off chain at once, then on chain with one signature.
    await relayCall(
      `/portal/accounts/${context.account.account_id}/members/${context.member.signerId}`,
      context.root.cookie,
      undefined,
      "DELETE",
    );
    const submittedBefore = local.sent.length;
    const { prepared, signed } = await rootRevokes(
      linkId,
      context.root.cookie,
      context.rootProfile,
      context.rootAccount,
      address,
    );
    expect(prepared.delivery).toBe("relay");
    expect(signed.status).toBe("submitted");
    expect(local.sent).toHaveLength(submittedBefore + 1);
    expect(await finalized(local, linkId, context.root.cookie)).toBe("finalized");
    expect(local.sent).toHaveLength(submittedBefore + 1);
    expect(await permissionInstalled(local, address, prepared.packages)).toBe(false);
    // Uninstalled: the member's next call no longer validates.
    expect(await next("1")).not.toBe(true);
    expect(await local.chain.rpc("eth_getBalance", [target, "latest"])).toBe("0x3e8");
  }, 180_000);

  it("a dapp that opted in receives the root-signed uninstall and submits it itself", async () => {
    const local = await startLocalArbitrumSepolia();
    rpcUpstream = local.chain.url;
    bundlerUpstream = local.bundlerUrl;
    const deployment = kernelDeployment({ chainId: 421_614 });
    const [ports] = createCetaneChainPorts({ 421614: { publicRpcUrls: [local.chain.url] } });
    if (!ports) throw new Error("no chain reads");
    const reads = ports.reads;
    const rootAccount = privateKeyToAccount(`0x${randomBytes(32).toString("hex")}`);
    const rootProfile = {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: rootAccount.address.toLowerCase() as `0x${string}`,
    } as const;
    const root = await relaySignIn(rootProfile, async (challenge) =>
      rootAccount.signMessage({ message: challenge.message ?? "" }),
    );
    const account = (
      await relayCall("/portal/accounts", root.cookie, {
        root_signer_id: root.signerId,
        creation_key: randomBytes(16).toString("hex"),
      })
    ).json as { account_id: string; address: `0x${string}` };

    // The dapp registers with revocation_delivery "dapp" and asks for a grant for its key.
    const redirectUri = `${dapp}/callback`;
    const client = (
      await relayCall("/oauth/clients", undefined, {
        client_name: "Opt-in dapp",
        redirect_uris: [redirectUri],
        revocation_delivery: "dapp",
      })
    ).json as { client_id: string; revocation_delivery: string };
    expect(client.revocation_delivery).toBe("dapp");
    const sessionAccount = privateKeyToAccount(`0x${randomBytes(32).toString("hex")}`);
    const target = `0x${"7d".repeat(20)}` as const;
    const now = Math.floor(Date.now() / 1000);
    const verifier = randomBytes(32).toString("base64url");
    const pushed = await fetch(`${relayBase}/oauth/par`, {
      method: "POST",
      body: new URLSearchParams({
        client_id: client.client_id,
        redirect_uri: redirectUri,
        response_type: "code",
        code_challenge: createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method: "S256",
        scope: "openid",
        authorization_details: JSON.stringify([
          {
            type: "oaath_grant",
            signer: {
              version: "oaath.operator-credential-profile/v1",
              kind: "ecdsa",
              address: sessionAccount.address.toLowerCase(),
            },
            policy: {
              version: "oaath.grant-policy/v1",
              calls: [{ target, selector: "0x12345678", valueLimit: "500", argumentEquals: [] }],
              validAfter: now,
              validUntil: now + 3600,
              perChainOperationLimit: { count: 3, intervalSeconds: null },
            },
            chains: [421614],
            expires_at: now + 7200,
            device_id: "opt-in-device",
          },
        ]),
      }),
    });
    const pushedBody = (await pushed.json()) as { request_uri?: string };
    if (!pushedBody.request_uri) throw new Error(`par ${pushed.status} ${JSON.stringify(pushedBody)}`);
    const grantId = pushedBody.request_uri.split(":").pop() ?? "";
    const prepared = (
      await relayCall(`/portal/transactions/${grantId}/prepare`, root.cookie, {
        signer_id: root.signerId,
        account_id: account.account_id,
      })
    ).json as { permission_request: unknown };
    const approval = prepareDerivedAccountPermissionApproval({
      request: parsePermissionRequest(prepared.permission_request),
      chainId: 421_614,
      account: account.address,
    });
    const rootKey = kernelKey({
      account: { address: rootProfile.address, sign: ({ hash }) => rootAccount.sign({ hash }) },
      validator: ECDSA_VALIDATOR,
    });
    const decision = await approval.sign(rootKey, now);
    const redirect = (
      await relayCall(`/portal/transactions/${grantId}/decision`, root.cookie, {
        outcome: "approved",
        signer_id: root.signerId,
        account_id: account.account_id,
        artifact: JSON.stringify(decision),
      })
    ).json as { redirect: string };
    const token = (await (
      await fetch(`${relayBase}/oauth/token`, {
        method: "POST",
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: client.client_id,
          code: new URL(redirect.redirect).searchParams.get("code") ?? "",
          code_verifier: verifier,
          redirect_uri: redirectUri,
        }),
      })
    ).json()) as {
      authorization_details: {
        permission_request: unknown;
        enable: Parameters<typeof materializeKernelPermission>[0]["approval"];
      }[];
    };
    const [detail] = token.authorization_details;
    if (!detail) throw new Error("no grant");

    // The dapp's first covered call installs its permission.
    const request = parsePermissionRequest(detail.permission_request);
    const owner = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: kernelKey({ credential: rootProfile, validator: ECDSA_VALIDATOR }),
      }),
      reads,
    });
    const session = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: kernelKey({
          account: {
            address: sessionAccount.address,
            sign: ({ hash }) => sessionAccount.sign({ hash }),
          },
          validator: ECDSA_VALIDATOR,
        }),
        policies: deriveSessionPolicyProfiles(request.policy),
      }),
      reads,
    });
    await local.chain.rpc("anvil_setBalance", [account.address, toHex(10n ** 18n)]);
    const first = await materializeKernelPermission({
      approval: detail.enable,
      runtime: session,
      grantId,
      account: await session.bindAccount({
        accountIndex: "0",
        initialPackages: owner.packages,
      }),
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "500", data: "0x12345678" }],
      gas: {
        callGasLimit: "900000",
        verificationGasLimit: "3000000",
        preVerificationGas: "150000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    expect(await handleOperation(local, first.prepared, first.signature)).toBe(true);

    // The root removes the dapp's signer, then signs the uninstall; the relay keeps it.
    const members = (await relayCall(`/portal/accounts/${account.account_id}/members`, root.cookie))
      .json as { members: { signer_id: string; grant_id: string | null }[] };
    const dappSigner = members.members.find((member) => member.grant_id === grantId);
    if (!dappSigner) throw new Error("no dapp signer");
    await relayCall(
      `/portal/accounts/${account.account_id}/members/${dappSigner.signer_id}`,
      root.cookie,
      undefined,
      "DELETE",
    );
    const sentBefore = local.sent.length;
    const { prepared: revocation, signed } = await rootRevokes(
      grantId,
      root.cookie,
      rootProfile,
      rootAccount,
      account.address,
    );
    expect(revocation.delivery).toBe("dapp");
    expect(signed.status).toBe("delivered");
    expect(local.sent).toHaveLength(sentBefore);

    // The dapp reads the signed operation and submits it through its own bundler.
    const delivered = (await relayCall(`/oauth/grants/${grantId}/revocation`)).json as {
      signed_operation: { request: { userOperation: Record<string, string> }; signature: string };
    };
    const op = delivered.signed_operation.request.userOperation;
    const quantity = (value: string | undefined) => toHex(BigInt(value ?? "0"));
    const sent = await fetch(local.bundlerUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_sendUserOperation",
        params: [
          {
            sender: op.sender,
            nonce: quantity(op.nonce),
            callData: op.callData,
            callGasLimit: quantity(op.callGasLimit),
            verificationGasLimit: quantity(op.verificationGasLimit),
            preVerificationGas: quantity(op.preVerificationGas),
            maxFeePerGas: quantity(op.maxFeePerGas),
            maxPriorityFeePerGas: quantity(op.maxPriorityFeePerGas),
            signature: delivered.signed_operation.signature,
          },
          deployment.entryPoint.address,
        ],
      }),
    });
    expect(((await sent.json()) as { result?: string }).result).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(await finalized(local, grantId, root.cookie)).toBe("finalized");
    expect(await permissionInstalled(local, account.address, revocation.packages)).toBe(false);
  }, 180_000);
});

describe("importing an existing account through the portal's chain-read proxy", () => {
  it("checks the root and lists modules, marking an executor installed elsewhere as outside", async () => {
    const local = await startLocalArbitrumSepolia();
    rpcUpstream = local.chain.url;
    const deployment = kernelDeployment({ chainId: 421_614 });
    const [ports] = createCetaneChainPorts({ 421614: { publicRpcUrls: [local.chain.url] } });
    if (!ports) throw new Error("no chain reads");
    const reads = ports.reads;
    /** A factory-deployed Kernel v4 account whose ECDSA root is `owner`. */
    async function deployAccount(owner: `0x${string}`, accountIndex: string) {
      const runtime = createKernelRuntime({
        deployment,
        operator: ownerOperator({
          key: kernelKey({
            credential: {
              version: "oaath.owner-credential-profile/v1",
              kind: "ecdsa",
              address: owner,
            },
            validator: ECDSA_VALIDATOR,
          }),
        }),
        reads,
      });
      const account = await runtime.bindAccount({
        accountIndex,
        initialPackages: runtime.packages,
      });
      if (account.state !== "counterfactual" || !("factoryDeployCalldata" in account))
        throw new Error("account already deployed");
      const hash = await local.stack.wallet.sendTransaction({
        to: account.factory,
        data: account.factoryDeployCalldata,
        gas: 3_000_000n,
      });
      await local.chain.client.waitForTransactionReceipt({ hash });
      return account.account;
    }
    const owned = await deployAccount(WALLET_ADDRESS, "70");
    const extended = await deployAccount(WALLET_ADDRESS, "71");
    const foreign = await deployAccount(`0x${"77".repeat(20)}`, "0");
    // Another app installs an executor on `extended`, as its own self-call.
    await local.chain.rpc("anvil_impersonateAccount", [extended]);
    await local.chain.rpc("anvil_setBalance", [extended, toHex(10n ** 18n)]);
    await local.chain.rpc("eth_sendTransaction", [
      {
        from: extended,
        to: extended,
        gas: toHex(500_000),
        data: encodeFunctionData({
          abi: parseAbi([
            "function installModule(uint256 moduleType, address module, bytes initData)",
          ]),
          functionName: "installModule",
          args: [
            2n,
            `0x${"e1".repeat(20)}`,
            encodeAbiParameters([{ type: "bytes" }, { type: "bytes" }], ["0x", "0x"]),
          ],
        }),
      },
    ]);

    const dappPage = await openDapp();
    const popup = await startLogin(dappPage);
    await click(popup, "::-p-text(E2E Wallet)");
    await popup.waitForSelector("#account-heading");
    await click(popup, "::-p-text(Import an existing account)");
    async function inspect(address: string) {
      await popup.waitForSelector("#import-address");
      await popup.$eval("#import-address", (node) => {
        (node as HTMLInputElement).value = "";
      });
      await popup.type("#import-address", address);
      await click(popup, "::-p-text(Check account)");
      await popup.waitForSelector(
        ".inventory, .check-fail, .check-unknown, #import-account [role=alert]",
      );
      return popup.$eval("#import-account", (node) => (node as HTMLElement).innerText);
    }

    const plain = await inspect(owned);
    expect(plain).toContain("This signer is the account's root owner.");
    expect(plain).toContain("No modules outside OAAth.");
    expect(plain).toMatch(/ECDSA validator\s*Validator · 0x845a…ce57\s*Root/u);
    const fingerprint = await popup.$eval(
      ".inventory",
      (node) => (node as HTMLElement).dataset.fingerprint,
    );
    expect(fingerprint).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(
      await popup.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);

    const withExecutor = await inspect(extended);
    expect(withExecutor).toContain("1 module outside OAAth.");
    expect(withExecutor).toMatch(/Unknown executor\s*Executor · 0xe1e1…e1e1\s*Outside OAAth/u);
    expect(
      await popup.$eval(".inventory", (node) => (node as HTMLElement).dataset.fingerprint),
    ).not.toBe(fingerprint);
    // Importing an account with modules outside OAAth needs an acknowledgment.
    const importButton = () =>
      popup.$eval("::-p-text(Import and sign)", (node) => (node as HTMLButtonElement).disabled);
    expect(await importButton()).toBe(true);
    await click(popup, ".acknowledge input");
    expect(await importButton()).toBe(false);

    expect(await inspect(foreign)).toContain(
      "This signer is not the account's root owner. Sign in with the signer that owns the account.",
    );
    expect(await popup.$(".inventory")).toBeNull();
    expect(await inspect(deployment.entryPoint.address)).toContain(
      "This contract is not a Kernel smart account: it has no upgradeable implementation.",
    );
    expect(await inspect(`0x${"12".repeat(20)}`)).toContain(
      "No contract is deployed at this address on Arbitrum Sepolia.",
    );

    // The root imports its account with one signature and logs in with it.
    await inspect(owned);
    const signatures = walletSignatures;
    await click(popup, "::-p-text(Import and sign)");
    const imported = await popup.waitForSelector(
      `button[aria-label='Smart account ${owned.toLowerCase()}, Owner']`,
    );
    expect(walletSignatures).toBe(signatures + 1);
    expect(await imported?.evaluate((node) => (node as HTMLElement).innerText)).toContain(
      "Imported",
    );
    await imported?.click();
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
    expect(payload.sub).toBe(owned.toLowerCase());
    expect(payload.oaath_account).toMatchObject({
      address: owned.toLowerCase(),
      kernelVersion: "0.4.0",
    });
    expect(payload.oaath_accounts).toContainEqual({
      address: owned.toLowerCase(),
      role: "root",
      status: "active",
    });

    // A second import of the same account is refused.
    const again = await openDapp();
    const retry = await startLogin(again);
    await click(retry, "::-p-text(E2E Wallet)");
    await retry.waitForSelector("#account-heading");
    await click(retry, "::-p-text(Import an existing account)");
    await retry.waitForSelector("#import-address");
    await retry.type("#import-address", owned);
    await click(retry, "::-p-text(Check account)");
    await click(retry, "::-p-text(Import and sign)");
    await retry.waitForSelector("::-p-text(This account is already in OAAth.)");

    // The relay proves the root on chain itself: an API call that skips the
    // portal's checks cannot import an EOA, a non-Kernel contract, or a
    // Kernel account whose root is another key.
    const ownerProfileHash = hashOwnerCredentialProfile({
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: WALLET_ADDRESS,
    });
    for (const address of [`0x${"12".repeat(20)}`, deployment.entryPoint.address, foreign]) {
      const issuedAt = Math.floor(Date.now() / 1000) - 5;
      const fingerprint = `0x${"22".repeat(32)}` as const;
      const signature = await WALLET.sign({
        hash: hashTypedData({
          domain: { name: "OAAth", version: "1" },
          types: {
            AccountImport: [
              { name: "account", type: "address" },
              { name: "ownerProfileHash", type: "bytes32" },
              { name: "inventoryFingerprint", type: "bytes32" },
              { name: "issuedAt", type: "uint64" },
              { name: "nonce", type: "string" },
            ],
          },
          primaryType: "AccountImport",
          message: {
            account: address as `0x${string}`,
            ownerProfileHash,
            inventoryFingerprint: fingerprint,
            issuedAt: BigInt(issuedAt),
            nonce: "direct-1",
          },
        }),
      });
      const refused = await retry.evaluate(
        async (body) => {
          const [signer] = JSON.parse(localStorage.getItem("oaath.portal.signers/v1") ?? "[]") as {
            signer_id: string;
          }[];
          const response = await fetch("/portal/accounts/import", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ ...body, root_signer_id: signer?.signer_id }),
          });
          return { status: response.status, body: await response.json() };
        },
        {
          address: address.toLowerCase(),
          inventory_fingerprint: fingerprint,
          issued_at: issuedAt,
          nonce: "direct-1",
          signature,
        },
      );
      expect(refused).toEqual({ status: 403, body: { error: { code: "relay_forbidden" } } });
    }
    await retry.close();
    await again.page.close();
    await dappPage.page.close();

    // Grants on the imported account: the portal prepares through the SDK's
    // reads-backed binding over its /rpc proxy, and signs only if the relay's
    // install digest is the same.
    const owner = owned.toLowerCase();
    const root = await browser.newPage();
    await root.setViewport({ width: 390, height: 844 });
    await installWallet(root);
    await root.goto(`${portal}/accounts`);
    await click(root, "::-p-text(E2E Wallet)");
    await click(root, `button[aria-label='Smart account ${owner}']`);
    await root.locator("button::-p-text(New policy)").click();
    await root.type("#policy-name", "Imported payments");
    await root.type(".policy-target", `0x${"ab".repeat(20)}`);
    await click(root, "::-p-text(Save policy)");
    await root.waitForSelector("button[aria-label='Edit Imported payments']");

    const device = await browser.createBrowserContext();
    const memberDapp = await openDapp(dapp, "#login:not([disabled])", device);
    const member = await startLogin(memberDapp);
    await addAuthenticator(member);
    await click(member, "::-p-text(Add signer)");
    await click(member, "::-p-text(New passkey)");
    await member.waitForSelector("::-p-text(This signer has no account yet.)");
    await click(member, "::-p-text(Link to an existing account)");
    await member.type("#link-account", owner);
    await click(member, "::-p-text(Request access)");
    const shared = await member.waitForSelector("#link-url");
    const linkUrl = (await shared?.evaluate((node) => node.textContent)) ?? "";
    await root.goto(linkUrl);
    await click(root, "::-p-text(E2E Wallet)");
    await click(root, "::-p-text(spend within “Imported payments”)");
    let before = walletSignatures;
    await click(root, "::-p-text(Approve and sign)");
    await root.waitForSelector("::-p-text(Signer added)");
    expect(walletSignatures).toBe(before + 1);
    await click(member, `button[aria-label='Smart account ${owner}, Signer']`);
    expect(await outcome(memberDapp.page)).toBe("signed-in");
    const reader = await device.newPage();
    await reader.goto(`${portal}/`);
    const linkId = linkUrl.split("/").pop() ?? "";
    const memberGrant = await reader.evaluate(async (id: string) => {
      const response = await fetch(`/portal/grants/${id}`);
      return (await response.json()) as {
        status: string;
        permission_request: { logicalAccount: { address?: string } };
        enable: { account: string };
      };
    }, linkId);
    expect(memberGrant.status).toBe("approved");
    expect(memberGrant.permission_request.logicalAccount.address).toBe(owner);
    expect(memberGrant.enable.account).toBe(owner);
    await device.close();

    // A dapp's oaath_grant on the imported account.
    const grantDapp = await browser.newPage();
    await grantDapp.goto(`${dapp}/`);
    const pushed = await pushGrant(grantDapp);
    const review = await openGrant(pushed);
    await click(review, "::-p-text(E2E Wallet)");
    await click(review, `button[aria-label='Smart account ${owner}, Owner']`);
    await review.waitForSelector("::-p-text(Approve and sign):not([disabled])");
    before = walletSignatures;
    const redeemed = await approveAndRedeem(grantDapp, review, pushed);
    expect(walletSignatures).toBe(before + 1);
    expect(redeemed.status).toBe(200);
    expect(redeemed.grant.enable.account).toBe(owner);
    expect(redeemed.read.status).toBe("approved");
    await review.close();
    await grantDapp.close();
    await root.close();

    // An owner operation on the imported account: no factory, executed at
    // its own address through the dapp's bundler.
    const target = `0x${"bf".repeat(20)}` as const;
    const operation = prepareOwnerOperation({
      account: {
        version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
        kind: "kernel",
        address: owner as `0x${string}`,
        kernelVersion: "0.4.0",
        entryPoint: { version: "0.9" },
        ownerCredential: {
          version: "oaath.owner-credential-profile/v1",
          kind: "ecdsa",
          address: WALLET_ADDRESS,
        },
      },
      chainId: 421_614,
      deployed: true,
      calls: [{ target, value: "1000", data: "0x" }],
      nonce: { lane: "0", sequence: "0" },
      gas: {
        callGasLimit: "900000",
        verificationGasLimit: "3000000",
        preVerificationGas: "150000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    expect(operation.request.userOperation.sender).toBe(owner);
    await local.chain.rpc("anvil_setBalance", [owner, toHex(10n ** 18n)]);
    const operationDapp = await browser.newPage();
    await operationDapp.goto(`${dapp}/`);
    const pushedOperation = await pushOperation(operationDapp, operation.request);
    const approval = await openGrant(pushedOperation);
    await click(approval, "::-p-text(E2E Wallet)");
    await click(approval, `button[aria-label='Smart account ${owner}, Owner']`);
    await approval.waitForSelector("#operation-heading");
    const shown = await approval.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(shown).toContain(target);
    expect(shown).not.toContain("Deployed by this transaction");
    await Promise.all([
      approval.waitForNavigation(),
      click(approval, "::-p-text(Approve and sign)"),
    ]);
    const operationCode = new URL(approval.url()).searchParams.get("code");
    if (!operationCode) throw new Error("no operation code");
    const released = await operationDapp.evaluate(
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
        return (await response.json()) as {
          authorization_details: { signed: unknown }[];
        };
      },
      {
        portal,
        clientId: pushedOperation.clientId,
        verifier: pushedOperation.verifier,
        code: operationCode,
      },
    );
    const verified = await verifyOwnerOperation(
      JSON.parse(JSON.stringify(released.authorization_details[0]?.signed)),
    );
    const sentBefore = local.sent.length;
    const submitted = await fetch(local.bundlerUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_sendUserOperation",
        params: [verified.userOperation, verified.entryPoint],
      }),
    });
    expect(((await submitted.json()) as { result: unknown }).result).toBe(
      operation.request.userOperationHash,
    );
    expect(local.sent).toHaveLength(sentBefore + 1);
    expect(await local.chain.rpc("eth_getBalance", [target, "latest"])).toBe("0x3e8");
    await approval.close();
    await operationDapp.close();
  });
});

/** The dapp PARs one exact owner operation the SDK prepared, as Keyline will. */
async function pushOperation(page: Page, request: unknown): Promise<PushedGrant> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return page.evaluate(
    async (input) => {
      const redirectUri = `${location.origin}/callback`;
      const registered = await fetch(`${input.portal}/oauth/clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_name: "E2E Keyline", redirect_uris: [redirectUri] }),
      });
      const { client_id: clientId } = (await registered.json()) as { client_id: string };
      const pushed = await fetch(`${input.portal}/oauth/par`, {
        method: "POST",
        body: new URLSearchParams({
          client_id: clientId,
          redirect_uri: redirectUri,
          response_type: "code",
          code_challenge: input.challenge,
          code_challenge_method: "S256",
          scope: "openid",
          state: "operation-state",
          authorization_details: JSON.stringify([
            { type: "oaath_operation", request: input.request },
          ]),
        }),
      });
      if (pushed.status !== 201) throw new Error(`par ${pushed.status}`);
      const { request_uri } = (await pushed.json()) as { request_uri: string };
      return { clientId, requestUri: request_uri, verifier: input.verifier };
    },
    { portal, challenge, verifier, request },
  );
}

describe("an owner operation approved by the account root and submitted by the dapp", () => {
  it("signs one exact operation in the portal, releases it once, and the dapp submits it", async () => {
    const local = await startLocalArbitrumSepolia();
    const target = `0x${"be".repeat(20)}` as const;
    // The wallet root's first registry account, from the login proof.
    const prepared = prepareOwnerOperation({
      account: {
        version: "oaath.kernel-account-profile/v1",
        kind: "kernel",
        accountIndex: "0",
        kernelVersion: "0.4.0",
        factoryRoute: "kernel_factory",
        entryPoint: { version: "0.9" },
        ownerCredential: {
          version: "oaath.owner-credential-profile/v1",
          kind: "ecdsa",
          address: WALLET_ADDRESS,
        },
      },
      chainId: 421_614,
      deployed: false,
      calls: [{ target, value: "1000", data: "0x" }],
      nonce: { lane: "0", sequence: "0" },
      gas: {
        callGasLimit: "900000",
        verificationGasLimit: "3000000",
        preVerificationGas: "150000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    const sender = prepared.request.userOperation.sender;
    await local.chain.rpc("anvil_setBalance", [sender, toHex(10n ** 18n)]);

    const dappPage = await browser.newPage();
    await dappPage.goto(`${dapp}/`);
    const pushed = await pushOperation(dappPage, prepared.request);
    const popup = await openGrant(pushed);
    await click(popup, "::-p-text(E2E Wallet)");
    // Only the operation's account is offered.
    await click(popup, `button[aria-label='Smart account ${sender}, Owner']`);
    await popup.waitForSelector("#operation-heading");
    const review = await popup.$eval("main", (node) => (node as HTMLElement).innerText);
    expect(review).toContain(target);
    expect(review).toContain("0.000000000000001 ETH");
    expect(review).toContain("Arbitrum Sepolia");
    expect(review).toContain("Deployed by this transaction");
    expect(review).toContain("Your account");
    expect(
      await popup.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await Promise.all([popup.waitForNavigation(), click(popup, "::-p-text(Approve and sign)")]);
    const code = new URL(popup.url()).searchParams.get("code");
    if (!code) throw new Error(`no code in ${popup.url()}`);

    const redeem = () =>
      dappPage.evaluate(
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
          return {
            status: response.status,
            body: (await response.json()) as Record<string, unknown>,
          };
        },
        { portal, clientId: pushed.clientId, verifier: pushed.verifier, code },
      );
    const token = await redeem();
    expect(token.status).toBe(200);
    const [detail] = token.body.authorization_details as { type: string; signed: unknown }[];
    expect(detail?.type).toBe("oaath_operation");
    // The code releases the signed operation once.
    expect((await redeem()).status).toBe(400);
    const stored = JSON.stringify(detail?.signed);

    // The dapp verifies the root's signature and submits through its own bundler.
    const verified = await verifyOwnerOperation(JSON.parse(stored));
    expect(verified.signed.request).toEqual(JSON.parse(JSON.stringify(prepared.request)));
    const bundler = async (method: string, params: unknown[]) => {
      const response = await fetch(local.bundlerUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      return ((await response.json()) as { result: unknown }).result;
    };
    expect(
      await bundler("eth_sendUserOperation", [verified.userOperation, verified.entryPoint]),
    ).toBe(prepared.request.userOperationHash);
    expect(await local.chain.rpc("eth_getBalance", [target, "latest"])).toBe("0x3e8");

    // Reload: only the stored artifact survives; observation sends nothing new.
    const reloaded = await verifyOwnerOperation(JSON.parse(stored));
    expect(
      await bundler("eth_getUserOperationReceipt", [reloaded.signed.request.userOperationHash]),
    ).toMatchObject({ success: true });
    expect(local.sent).toHaveLength(1);
    await popup.close();
    await dappPage.close();
  });
});
