/**
 * The built portal in headless Chrome against a stub relay whose responses are
 * the typed `src/api.ts` shapes. The real relay end-to-end is a later proof.
 */
import { access, readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer, { type Browser, type Page } from "puppeteer-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  CreateAccountResponse,
  PortalAccount,
  PortalTransaction,
  RedirectResponse,
  RegisterSignerResponse,
  SignerAccountsResponse,
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

async function stubRelay(path: string, method: string, body: unknown) {
  if (path === "/portal/transactions/par-1" && method === "GET")
    return {
      transaction_id: "par-1",
      client_id: "client-1",
      client_name: "Example Dapp",
      redirect_origin: origin,
      authorization_details: [],
      expires_at: Math.floor(Date.now() / 1000) + 600,
    } satisfies PortalTransaction;
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
    accounts.set(signer, [{ ...created, role: "root" }]);
    return created;
  }
  if (path === "/portal/transactions/par-1/decision" && method === "POST")
    return { redirect: `${origin}/dapp/callback?code=code-1&state=s` } satisfies RedirectResponse;
  return null;
}

beforeAll(async () => {
  await access(join(DIST, "index.html"));
  server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    let raw = "";
    for await (const chunk of request) raw += chunk;
    const body = raw ? (JSON.parse(raw) as unknown) : null;
    if (url.pathname.startsWith("/portal/")) {
      calls.push({ method: request.method ?? "GET", path: url.pathname, body });
      const result = await stubRelay(url.pathname, request.method ?? "GET", body);
      return result === null
        ? json(response, 404, { error: "not_found", error_code: "relay_not_found" })
        : json(response, 200, result);
    }
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

async function openPortal(seed: readonly RememberedSigner[]): Promise<Page> {
  const page = await browser.newPage();
  await page.setViewport({ width: 390, height: 844 });
  await page.evaluateOnNewDocument((signers: string) => {
    localStorage.setItem("oaath.portal.signers/v1", signers);
  }, JSON.stringify(seed));
  await page.goto(
    `${origin}/authorize?client_id=client-1&request_uri=urn:ietf:params:oauth:request_uri:par-1`,
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
    ).toBe(true);
    await capture(page, "2-accounts-empty");
    await clickText(page, "Create account");
    await page.waitForSelector("::-p-text(0xabab…abab)");
    await capture(page, "3-account-created");
    await Promise.all([page.waitForNavigation(), clickText(page, "0xabab…abab")]);
    expect(page.url()).toBe(`${origin}/dapp/callback?code=code-1&state=s`);
    expect(calls.filter((call) => call.method === "POST")).toEqual([
      { method: "POST", path: "/portal/accounts", body: { root_signer_id: "signer-wallet" } },
      {
        method: "POST",
        path: "/portal/transactions/par-1/decision",
        body: {
          signer_id: "signer-wallet",
          account_id: "account-signer-wallet",
          outcome: "approve",
        },
      },
    ]);
    await page.close();
  });

  it("adds a passkey signer without signing anything, and offers the phone as coming soon", async () => {
    calls.length = 0;
    const page = await openPortal([]);
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
    expect(await page.$eval("::-p-text(Phone)", (node) => node.closest("button")?.disabled)).toBe(
      true,
    );
    await capture(page, "4-add-signer");
    await clickText(page, "New passkey");
    await page.waitForSelector("#account-heading");
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

  it("connects an EIP-6963 wallet with eth_requestAccounts only", async () => {
    calls.length = 0;
    const page = await browser.newPage();
    await page.evaluateOnNewDocument(() => {
      const methods: string[] = [];
      Object.assign(window, { walletMethods: methods });
      const provider = {
        request: async ({ method }: { method: string }) => {
          methods.push(method);
          return [`0x${"22".repeat(20)}`];
        },
      };
      window.addEventListener("eip6963:requestProvider", () =>
        window.dispatchEvent(
          new CustomEvent("eip6963:announceProvider", {
            detail: Object.freeze({
              info: { uuid: "wallet-1", name: "Fixture Wallet", icon: "", rdns: "test.fixture" },
              provider,
            }),
          }),
        ),
      );
    });
    await page.goto(
      `${origin}/authorize?client_id=client-1&request_uri=urn:ietf:params:oauth:request_uri:par-1`,
    );
    await clickText(page, "Add signer");
    await clickText(page, "Fixture Wallet");
    await page.waitForSelector("#account-heading");
    expect(
      await page.evaluate(() => (window as unknown as { walletMethods: string[] }).walletMethods),
    ).toEqual(["eth_requestAccounts"]);
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
});
