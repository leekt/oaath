/**
 * Login with OAAth end to end, with no stub on the authorization path:
 *
 * - the real Rust relay binary, configured as production runs it (no
 *   OAATH_CONFIG, kid from the key thumbprint) with the memory store and a
 *   throwaway ES256 key;
 * - the real portal Worker module, run in Node in front of the built SPA and
 *   bound to that relay (the Workers VPC binding becomes a loopback fetch);
 * - headless Chrome driving a dapp page on another origin through dynamic
 *   client registration, PAR, the portal popup, and the code exchange.
 *
 * The id_token is verified against `/oauth/jwks` with `jose`.
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
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker, { type Env, ORIGIN } from "../worker/index.js";

const DIST = fileURLToPath(new URL("../dist", import.meta.url));
const RELAY_DIR = fileURLToPath(new URL("../../relay", import.meta.url));
const WALLET_ADDRESS = `0x${"5a".repeat(20)}`;

let browser: Browser;
let relay: ReturnType<typeof spawn> | undefined;
const servers: Server[] = [];
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

/** A dapp on a different origin: one page and its callback. */
async function startDapp() {
  const port = await listen((request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end(
      `<!doctype html><title>${request.url?.startsWith("/callback") ? "callback" : "dapp"}</title>`,
    );
  });
  return `http://127.0.0.1:${port}`;
}

interface Pushed {
  readonly clientId: string;
  readonly requestUri: string;
  readonly verifier: string;
  readonly state: string;
  readonly nonce: string;
}

/** Registers a client (once) and pushes one authorization request from the dapp page. */
async function pushRequest(page: Page, clientId?: string): Promise<Pushed> {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return page.evaluate(
    async (input) => {
      let id = input.clientId;
      if (!id) {
        const registered = await fetch(`${input.portal}/oauth/clients`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            client_name: "E2E Dapp",
            redirect_uris: [`${location.origin}/callback`],
          }),
        });
        if (registered.status !== 201 && registered.status !== 200)
          throw new Error(`register ${registered.status}`);
        id = ((await registered.json()) as { client_id: string }).client_id;
      }
      const state = crypto.randomUUID();
      const nonce = crypto.randomUUID();
      const pushed = await fetch(`${input.portal}/oauth/par`, {
        method: "POST",
        body: new URLSearchParams({
          client_id: id,
          redirect_uri: `${location.origin}/callback`,
          response_type: "code",
          code_challenge: input.challenge,
          code_challenge_method: "S256",
          scope: "openid",
          state,
          nonce,
        }),
      });
      if (pushed.status !== 201) throw new Error(`par ${pushed.status}`);
      const { request_uri } = (await pushed.json()) as { request_uri: string };
      return { clientId: id, requestUri: request_uri, verifier: input.verifier, state, nonce };
    },
    { portal, challenge, verifier, clientId: clientId ?? null },
  );
}

/** The dapp's token request: a cross-origin form POST answered through CORS. */
function exchange(page: Page, pushed: Pushed, code: string) {
  return page.evaluate(
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
      return { status: response.status, body: (await response.json()) as Record<string, unknown> };
    },
    { portal, clientId: pushed.clientId, verifier: pushed.verifier, code },
  );
}

/** The portal popup with an EIP-6963 wallet that answers eth_requestAccounts only. */
async function openPortal(pushed: Pushed) {
  const page = await browser.newPage();
  await page.setViewport({ width: 390, height: 844 });
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
  const query = new URLSearchParams({ client_id: pushed.clientId, request_uri: pushed.requestUri });
  await page.goto(`${portal}/authorize?${query}`);
  await page.waitForSelector("#signer-heading");
  return page;
}

async function click(page: Page, selector: string) {
  const element = await page.waitForSelector(selector);
  await element?.click();
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
});

describe("Login with OAAth against the real relay", () => {
  let first: Pushed;

  it("logs in with a wallet signer and a new account, and issues a verifiable id_token", async () => {
    const dappPage = await browser.newPage();
    await dappPage.goto(`${dapp}/`);
    first = await pushRequest(dappPage);

    const popup = await openPortal(first);
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
    await Promise.all([popup.waitForNavigation(), account?.click()]);

    const callback = new URL(popup.url());
    expect(callback.origin + callback.pathname).toBe(`${dapp}/callback`);
    expect(callback.searchParams.get("state")).toBe(first.state);
    expect(callback.searchParams.get("iss")).toBe(portal);
    const code = callback.searchParams.get("code");
    if (!code) throw new Error("no authorization code");

    const token = await exchange(dappPage, first, code);
    expect(token.status).toBe(200);
    const jwks = createRemoteJWKSet(new URL(`${portal}/oauth/jwks`));
    const { payload, protectedHeader } = await jwtVerify(String(token.body.id_token), jwks, {
      issuer: portal,
      audience: first.clientId,
      algorithms: ["ES256"],
    });
    expect(protectedHeader.kid).toBe(idTokenKid);
    expect(payload.sub).toBe(shown);
    expect(payload.nonce).toBe(first.nonce);
    expect(payload.verified).toBe(false);
    expect(payload.signer).toMatchObject({
      kind: "ecdsa",
      profile: { kind: "ecdsa", address: WALLET_ADDRESS },
    });
    expect(payload.oaath_account).toMatchObject({ kind: "kernel", kernelVersion: "0.4.0" });

    const replay = await exchange(dappPage, first, code);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    await popup.close();
    await dappPage.close();
  });

  it("returns access_denied when the user cancels", async () => {
    const dappPage = await browser.newPage();
    await dappPage.goto(`${dapp}/`);
    const pushed = await pushRequest(dappPage, first.clientId);
    const popup = await openPortal(pushed);
    // The wallet signer from the first login is remembered in this browser.
    await popup.waitForSelector("::-p-text(E2E Wallet)");
    await Promise.all([
      popup.waitForNavigation(),
      click(popup, "::-p-text(Cancel and return to the app)"),
    ]);
    const callback = new URL(popup.url());
    expect(callback.origin + callback.pathname).toBe(`${dapp}/callback`);
    expect(callback.searchParams.get("error")).toBe("access_denied");
    expect(callback.searchParams.get("state")).toBe(pushed.state);
    expect(callback.searchParams.get("code")).toBeNull();
    await popup.close();
    await dappPage.close();
  });
});
