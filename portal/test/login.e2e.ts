/**
 * Login with OAAth end to end, with no stub on the authorization path:
 *
 * - the real Rust relay binary, configured as production runs it (no
 *   OAATH_CONFIG, kid from the key thumbprint) with the memory store and a
 *   throwaway ES256 key;
 * - the real portal Worker module, run in Node in front of the built SPA and
 *   bound to that relay (the Workers VPC binding becomes a loopback fetch);
 * - the examples/oauth-login dapp on another origin, whose page calls the
 *   SDK's `loginWithOAAth` and whose redirect page runs `completeOAAthLogin`;
 * - headless Chrome clicking through the SDK's popup.
 *
 * The SDK verifies the id_token; the test verifies it again against
 * `/oauth/jwks` with `jose`.
 */
import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { access, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { calculateJwkThumbprint, createRemoteJWKSet, type JWK, jwtVerify } from "jose";
import puppeteer, { type Browser, type Page } from "puppeteer-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker, { type Env, ORIGIN } from "../worker/index.js";

const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const RELAY_DIR = fileURLToPath(new URL("../../relay", import.meta.url));
const WALLET_ADDRESS = `0x${"5a".repeat(20)}`;
const EXAMPLE = fileURLToPath(new URL("../../examples/oauth-login/server.mjs", import.meta.url));

let browser: Browser;
let relay: ReturnType<typeof spawn> | undefined;
const servers: Server[] = [];
const closers: (() => Promise<void>)[] = [];
let portal: string;
let dapp: string;
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

/** The examples/oauth-login dapp, on another origin than the portal. */
async function startDapp() {
  const { startOAuthLoginExample } = (await import(EXAMPLE)) as {
    startOAuthLoginExample(input: {
      issuer: string;
      host: string;
      port: number;
    }): Promise<{ url: string; close(): Promise<void> }>;
  };
  const example = await startOAuthLoginExample({ issuer: portal, host: "127.0.0.1", port: 0 });
  closers.push(example.close);
  return example.url;
}

/** An EIP-6963 wallet in every document of `page` that answers eth_requestAccounts only. */
async function installWallet(page: Page) {
  await page.evaluateOnNewDocument((address: string) => {
    const methods: string[] = [];
    Object.assign(window, { walletMethods: methods });
    const provider = {
      request: async ({ method }: { method: string }) => {
        methods.push(method);
        if (method !== "eth_requestAccounts") throw new Error("unexpected wallet method");
        return [address];
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
async function openDapp() {
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
  await page.goto(`${dapp}/`);
  await page.waitForSelector("#login:not([disabled])");
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
) {
  const opened = browser.waitForTarget((target) => target.opener() === dappPage.page.target());
  await click(dappPage.page, "#login");
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
