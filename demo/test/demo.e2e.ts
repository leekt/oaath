/**
 * The hosted demo end to end, with no stub on the authorization path and no
 * public network:
 *
 * - the real Rust relay binary (memory store, throwaway ES256 key);
 * - the real portal Worker module in front of the built portal SPA;
 * - the real demo Worker module in front of the built demo SPA, on its own
 *   origin, proxying to local Arbitrum Sepolia (Anvil 421614 with the pinned
 *   Kernel stack) and a fixture ERC-4337 bundler that, like bundle_rs in fast
 *   mode, takes zero-fee operations and pays their gas from its own wallet;
 * - headless Chrome clicking through the demo and the SDK's popups.
 *
 * Root login → invite → root Grant and relay-paid test call → relay-paid owner
 * operation → member joins with a passkey → member Grant pending → root
 * approves → member redeems after a reload → member's relay-paid test call
 * executes → the automation service's relay-paid ping. No account is funded.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type AutomationService,
  configFromEnv,
  loadDefinitions,
  startAutomationService,
} from "@oaath/automation-server";
import { kernelDeployment } from "@oaath/sdk/kernel";
import puppeteer, { type Browser, type Page, type Protocol } from "puppeteer-core";
import { decodeEventLog, encodeFunctionData, hashTypedData, toHex } from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  startCluster,
  type TestCluster,
} from "../../packages/automation-server/test/support/postgres.js";
import portalWorker, {
  ORIGIN as PORTAL_ORIGIN,
  type Env as PortalEnv,
} from "../../portal/worker/index.js";
import demoWorker, { type Env as DemoEnv } from "../worker/index.js";

const DEMO_DIST = fileURLToPath(new URL("../dist", import.meta.url));
const PORTAL_DIST = fileURLToPath(new URL("../../portal/dist", import.meta.url));
const RELAY_DIR = fileURLToPath(new URL("../../relay", import.meta.url));
const ANVIL = fileURLToPath(
  new URL("../../packages/testing/src/anvil-process.mjs", import.meta.url),
);
const V33 = fileURLToPath(
  new URL("../../packages/sdk/test/fixtures/kernel-v33-deployments.json", import.meta.url),
);
const PING = fileURLToPath(new URL("../automation/demo-ping.automation.json", import.meta.url));
const DEMO_ORIGIN = "https://oaath-demo.taek.tech";
const WALLET = privateKeyToAccount(`0x${"5a".repeat(32)}`);
const WALLET_ADDRESS = WALLET.address.toLowerCase() as `0x${string}`;
let walletSignatures = 0;

let browser: Browser;
let relay: ReturnType<typeof spawn> | undefined;
const servers: Server[] = [];
const closers: (() => Promise<void>)[] = [];
let portal: string;
let relayBase: string;
let rpcUpstream = "http://127.0.0.1:9/";
let bundlerUpstream = "http://127.0.0.1:9/";

async function listen(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
  host = "127.0.0.1",
) {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
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

async function body(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

/** A loopback hop to whichever upstream the test configured later. */
async function hop(target: () => string) {
  return listen(async (incoming, outgoing) => {
    try {
      const upstream = await fetch(target(), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await body(incoming),
      });
      outgoing.writeHead(upstream.status, { "content-type": "application/json" });
      outgoing.end(Buffer.from(await upstream.arrayBuffer()));
    } catch {
      outgoing.writeHead(502).end();
    }
  });
}

async function startRelay(issuer: string) {
  const cargo =
    (await firstExisting([process.env.CARGO, join(homedir(), ".cargo/bin/cargo")])) ?? "cargo";
  const build = spawnSync(cargo, ["build", "-q", "-p", "oaath-relay"], {
    cwd: RELAY_DIR,
    stdio: "inherit",
  });
  if (build.status !== 0) throw new Error("cargo build -p oaath-relay failed");
  const work = await mkdtemp(join(tmpdir(), "oaath-demo-e2e-"));
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  await writeFile(join(work, "id-token.pem"), privateKey.export({ type: "pkcs8", format: "pem" }));
  const port = await freePort();
  const rpcPort = await hop(() => rpcUpstream);
  const bundlerPort = await hop(() => bundlerUpstream);
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

function assets(dist: string, origin: string) {
  return {
    async fetch(request: Request) {
      const path = new URL(request.url, origin).pathname;
      try {
        const file = await readFile(join(dist, path === "/" ? "index.html" : path));
        const type = path.endsWith(".js")
          ? "text/javascript"
          : path.endsWith(".css")
            ? "text/css"
            : path.endsWith(".woff2")
              ? "font/woff2"
              : "text/html";
        return new Response(new Uint8Array(file), { headers: { "content-type": type } });
      } catch {
        return new Response("Not found", { status: 404 });
      }
    },
  };
}

/** Node's HTTP server in front of a Worker module that pins its public origin. */
async function serveWorker(
  origin: string,
  fetchWorker: (request: Request) => Promise<Response>,
  host: string,
) {
  const port = await listen(async (incoming, outgoing) => {
    const local = `http://${host}:${port}`;
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (typeof value !== "string") continue;
      headers.set(name, name === "origin" && value === local ? origin : value);
    }
    const payload = await body(incoming);
    const response = await fetchWorker(
      new Request(`${origin}${incoming.url ?? "/"}`, {
        method: incoming.method ?? "GET",
        headers,
        body: payload.length > 0 ? payload : null,
      }),
    );
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      // Plain-http loopback cannot honour the production upgrade directive.
      responseHeaders[name] =
        name === "content-security-policy"
          ? value.replace("; upgrade-insecure-requests", "")
          : value;
    });
    outgoing.writeHead(response.status, responseHeaders);
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  }, host);
  return `http://${host}:${port}`;
}

async function startPortal() {
  const env: PortalEnv = {
    get RPC_UPSTREAM_421614() {
      return rpcUpstream;
    },
    RPC_LIMIT: { limit: async () => ({ success: true }) },
    WRITE_LIMIT: { limit: async () => ({ success: true }) },
    ASSETS: assets(PORTAL_DIST, PORTAL_ORIGIN),
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
  return serveWorker(PORTAL_ORIGIN, (request) => portalWorker.fetch(request, env), "localhost");
}

/** Anvil 421614 with the pinned Kernel stack and a fixture ERC-4337 bundler. */
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
  await chain.client.waitForTransactionReceipt({
    hash: await stack.wallet.sendTransaction({
      to: deployment.create2Deployer,
      data: v33.ecdsaValidator.deploymentInput,
      gas: 10_000_000n,
    }),
  });

  const sent: UserOperation<"0.9">[] = [];
  const receipts = new Map<string, unknown>();
  const bundlerPort = await listen(async (request, response) => {
    const rpc = JSON.parse(String(await body(request))) as {
      id: number;
      method: string;
      params: unknown[];
    };
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
      // The relay's wallet pays gas, as bundle_rs's fast path: no account funds.
      const wire = rpc.params[0] as Record<string, string>;
      const big = (value: string | undefined) => (value === undefined ? undefined : BigInt(value));
      const operation = {
        ...wire,
        nonce: BigInt(wire.nonce ?? "0"),
        callGasLimit: BigInt(wire.callGasLimit ?? "0"),
        verificationGasLimit: BigInt(wire.verificationGasLimit ?? "0"),
        preVerificationGas: BigInt(wire.preVerificationGas ?? "0"),
        maxFeePerGas: BigInt(wire.maxFeePerGas ?? "0"),
        maxPriorityFeePerGas: BigInt(wire.maxPriorityFeePerGas ?? "0"),
        paymasterVerificationGasLimit: big(wire.paymasterVerificationGasLimit),
        paymasterPostOpGasLimit: big(wire.paymasterPostOpGasLimit),
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
        // As bundle_rs: the field is omitted when the operation has no paymaster.
        ...(operation.paymaster ? { paymaster: operation.paymaster } : {}),
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

  return {
    chain,
    sent,
    bundlerUrl: `http://127.0.0.1:${bundlerPort}`,
  };
}

async function installWallet(page: Page) {
  await page.exposeFunction("e2eWalletSignTypedData", (json: string) => {
    walletSignatures += 1;
    return WALLET.sign({ hash: hashTypedData(JSON.parse(json)) });
  });
  await page.exposeFunction("e2eWalletPersonalSign", (raw: `0x${string}`) =>
    WALLET.signMessage({ message: { raw } }),
  );
  await page.evaluateOnNewDocument((address: string) => {
    type Signing = {
      e2eWalletSignTypedData(json: string): Promise<string>;
      e2eWalletPersonalSign(raw: string): Promise<string>;
    };
    const signing = window as unknown as Signing;
    const provider = {
      request: async ({ method, params }: { method: string; params?: [string, string] }) => {
        if (method === "eth_requestAccounts") return [address];
        if (method === "personal_sign" && params?.[1] === address)
          return signing.e2eWalletPersonalSign(params[0]);
        if (method === "eth_signTypedData_v4" && params?.[0] === address)
          return signing.e2eWalletSignTypedData(params[1]);
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

async function withCredential(page: Page, credentials: readonly Protocol.WebAuthn.Credential[]) {
  const authenticator = await addAuthenticator(page);
  for (const credential of credentials)
    await authenticator.session.send("WebAuthn.addCredential", {
      authenticatorId: authenticator.id,
      credential,
    });
}

async function click(page: Page, selector: string) {
  await page.waitForFunction(() =>
    document.getAnimations().every((animation) => animation.playState !== "running"),
  );
  await page.locator(selector).click();
}

/** Each demo page's PARs wait until its popup is instrumented; delayed, never altered. */
const releases = new WeakMap<Page, () => void>();

/** Opens the demo, ready once its SDK connection is up. */
async function openDemo(url: string, context: Pick<Browser, "newPage"> = browser) {
  const page = await context.newPage();
  await page.setViewport({ width: 390, height: 844 });
  let gate = Promise.resolve();
  releases.set(page, () => {});
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/oauth/par") void gate.then(() => request.continue());
    else void request.continue();
  });
  const hold = () => {
    gate = new Promise<void>((resolve) => releases.set(page, resolve));
  };
  hold();
  Object.assign(page, { hold });
  await page.goto(url);
  await page.waitForSelector("#grant:not([disabled])");
  return page;
}

/**
 * Clicks `button` on the demo and returns the SDK's popup with the fixture
 * wallet, once `ready` shows: the signer screen, or for a request after the
 * page's login, the screen that asks only for the signature.
 */
async function popupFrom(page: Page, button: string, ready = "#signer-heading") {
  (page as Page & { hold(): void }).hold();
  const opened = browser.waitForTarget((target) => target.opener() === page.target());
  await click(page, button);
  const popup = await (await opened).page();
  if (!popup) throw new Error("no popup");
  await popup.setViewport({ width: 390, height: 844 });
  await installWallet(popup);
  releases.get(page)?.();
  await popup.waitForSelector(ready);
  return popup;
}

async function outcome(page: Page, expected: string, timeout = 30_000) {
  await page.waitForSelector(`#result[data-outcome='${expected}']`, { timeout });
}

async function text(page: Page, selector: string) {
  const disclosure = await page.$eval(selector, (node) => {
    const details = node.closest("details");
    return details && !details.open ? details.id : null;
  });
  if (disclosure) await click(page, `#${disclosure} > summary`);
  const value = await page.$eval(selector, (node) => (node as HTMLElement).innerText);
  if (disclosure) await click(page, `#${disclosure} > summary`);
  return value;
}

/** Optional visual evidence from the real, isolated flows; never live accounts. */
async function capture(page: Page, name: string) {
  const directory = process.env.OAATH_DEMO_SCREENSHOTS;
  if (!directory) return;
  await mkdir(directory, { recursive: true });
  for (const [viewport, width, height] of [
    ["desktop", 1440, 1000],
    ["mobile", 390, 844],
  ] as const) {
    await page.setViewport({ width, height });
    await page.evaluate(async () => {
      await document.fonts.ready;
      window.scrollTo(0, 0);
    });
    await page.waitForFunction(() => window.scrollY === 0);
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.screenshot({ path: join(directory, `${name}-${viewport}.png`), fullPage: true });
  }
}

/** A relay-paid operation: zero fees and no paymaster. */
function expectRelayPaid(operation: UserOperation<"0.9"> | undefined) {
  expect(operation?.maxFeePerGas).toBe(0n);
  expect(operation?.maxPriorityFeePerGas).toBe(0n);
  expect(operation?.paymaster ?? null).toBeNull();
}

let demo: string;
let local: Awaited<ReturnType<typeof startLocalArbitrumSepolia>>;
let automation: AutomationService | undefined;
let cluster: TestCluster | undefined;

beforeAll(async () => {
  await access(join(DEMO_DIST, "index.html"));
  await access(join(PORTAL_DIST, "index.html"));
  portal = await startPortal();
  relayBase = await startRelay(portal);
  local = await startLocalArbitrumSepolia();
  rpcUpstream = local.chain.url;
  bundlerUpstream = local.bundlerUrl;
  const env: { -readonly [K in keyof DemoEnv]: DemoEnv[K] } = {
    ASSETS: assets(DEMO_DIST, DEMO_ORIGIN),
    DEMO_ORIGIN,
    OAATH_ISSUER: portal,
    OAATH_CLIENT_ID: "",
    EXPLORER_TX_URL: "https://sepolia.arbiscan.io/tx/",
    CHAIN_RPC_URL: local.chain.url,
    // The bundle_rs VPC binding, pointed at the fixture bundler.
    BUNDLER: {
      fetch: (request: Request) =>
        fetch(local.bundlerUrl, {
          method: request.method,
          headers: request.headers,
          body: request.body,
          duplex: "half",
        } as RequestInit),
    },
    RPC_LIMIT: { limit: async () => ({ success: true }) },
    SEND_LIMIT: { limit: async () => ({ success: true }) },
  };
  demo = await serveWorker(DEMO_ORIGIN, (request) => demoWorker.fetch(request, env), "127.0.0.1");
  // Registered once, as for the hosted demo; the Worker serves it in /config.json.
  const registered = await fetch(`${portal}/oauth/clients`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "OAAth Demo", redirect_uris: [`${demo}/callback`] }),
  });
  env.OAATH_CLIENT_ID = ((await registered.json()) as { client_id: string }).client_id;

  // The automation service the demo schedules on: its own OAuth client at the
  // same issuer, a throwaway PostgreSQL, and the same chain and relay-paid bundler.
  cluster = await startCluster();
  const servicePort = await freePort();
  const serviceUrl = `http://127.0.0.1:${servicePort}`;
  const automationClient = await fetch(`${portal}/oauth/clients`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "OAAth Automation",
      redirect_uris: [`${serviceUrl}/v1/oauth/callback`],
    }),
  });
  const appToken = randomBytes(32).toString("hex");
  automation = await startAutomationService(
    configFromEnv(
      {
        DATABASE_URL: await cluster.database(),
        AUTOMATION_SEAL_KEY: randomBytes(32).toString("hex"),
        AUTOMATION_PUBLIC_URL: serviceUrl,
        AUTOMATION_LISTEN: `127.0.0.1:${servicePort}`,
        OAATH_ISSUER: portal,
        OAATH_CLIENT_ID: ((await automationClient.json()) as { client_id: string }).client_id,
        AUTOMATION_APPLICATIONS: `demo:${createHash("sha256").update(appToken).digest("hex")}`,
        AUTOMATION_ALLOWED_ORIGINS: demo,
        AUTOMATION_RPC_URL_421614: local.chain.url,
        AUTOMATION_BUNDLER_URL_421614: local.bundlerUrl,
        AUTOMATION_RELAY_PAYS_GAS_421614: "true",
      },
      loadDefinitions([PING]),
    ),
  );
  env.AUTOMATION_URL = serviceUrl;
  env.AUTOMATION_APP_TOKEN = appToken;

  const executablePath = await firstExisting([
    process.env.PUPPETEER_EXECUTABLE_PATH,
    process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ]);
  if (!executablePath) throw new Error("Chrome is required for the demo end-to-end test");
  browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: ["--no-sandbox", "--disable-background-networking"],
  });
});

afterAll(async () => {
  await browser?.close();
  await automation?.close();
  cluster?.stop();
  relay?.kill("SIGTERM");
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
  await Promise.all(closers.map((close) => close()));
});

describe("the hosted OAAth demo on a local Arbitrum Sepolia", () => {
  it("explains a failed startup and keeps actions unavailable", async () => {
    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      if (new URL(request.url()).pathname === "/config.json")
        void request.respond({ status: 503, contentType: "application/json", body: "{}" });
      else void request.continue();
    });
    await page.goto(demo);
    await page.waitForFunction(() =>
      document.getElementById("startup-message")?.textContent?.includes("couldn't connect"),
    );
    expect(await page.$eval("#login", (node) => (node as HTMLButtonElement).disabled)).toBe(true);
    expect(await page.$eval("#grant", (node) => (node as HTMLButtonElement).disabled)).toBe(true);
    await capture(page, "unavailable");
    await page.goto(`${demo}/callback`);
    await capture(page, "callback");
    await page.close();
  });
  it("root logs in, grants and sends relay-paid; a member joins, waits, is approved and sends", async () => {
    // 1. The root logs in with a new wallet signer and a new account.
    const root = await openDemo(`${demo}/`);
    await capture(root, "start");
    let popup = await popupFrom(root, "#login");
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "#add-wallet-method");
    await click(popup, "[aria-label='Available wallets'] button::-p-text(E2E Wallet)");
    await click(popup, "::-p-text(Create account)");
    const owned = await popup.waitForSelector("button[aria-label^='Smart account 0x']");
    const address = /0x[0-9a-f]{40}/u.exec(
      (await owned?.evaluate((node) => node.getAttribute("aria-label"))) ?? "",
    )?.[0] as `0x${string}`;
    await owned?.click();
    await outcome(root, "signed-in");
    expect(await text(root, "#identity-title")).toBe("Owner · signed in");
    expect(await text(root, "#login-badge")).toBe("Signed in");
    await capture(root, "signed-in");
    const identity = JSON.parse(await text(root, "#identity"));
    expect(identity).toMatchObject({
      account: address,
      role: "root",
      verified: true,
      oaath_accounts: [{ address, role: "root", status: "active" }],
    });

    // 2. The invite link names this demo and the account.
    expect(await text(root, "#invite-url")).toBe(`${demo}/?invite=${address}`);

    // 3. The root's Grant: the popup opens on the review for the signer and
    // account the login chose, and asks for one signature only.
    popup = await popupFrom(root, "#grant", "#review-heading");
    expect(await popup.$("#signer-heading")).toBeNull();
    expect(await popup.$("#account-heading")).toBeNull();
    expect(await text(popup, "main")).toContain(`${address.slice(0, 6)}…${address.slice(-4)}`);
    await popup.waitForSelector("::-p-text(Approve and sign):not([disabled])");
    expect(await text(popup, "main")).toContain("0x000000000000000000000000000000000000dead");
    const signatures = walletSignatures;
    await click(popup, "::-p-text(Approve and sign)");
    await outcome(root, "granted");
    expect(walletSignatures).toBe(signatures + 1);
    expect(await text(root, "#account")).toBe(address);
    expect(await root.$eval("#sponsored", (node) => (node as HTMLElement).hidden)).toBe(false);
    expect(await text(root, "#send-badge")).toBe("Ready to send");
    expect(await text(root, "#grant")).toBe("Request new permission");
    expect(await root.$eval("#grant", (node) => node.classList.contains("button-outline"))).toBe(
      true,
    );
    await capture(root, "permission");

    // 4. The relay-paid test call deploys, enables and executes with an unfunded account.
    expect(await local.chain.rpc("eth_getBalance", [address, "latest"])).toBe("0x0");
    await click(root, "#send");
    await outcome(root, "finalized");
    expect(await text(root, "#send-badge")).toBe("Call finalized");
    await capture(root, "completed");
    expect(await text(root, "#operation")).toMatch(
      /UserOperation 0x[0-9a-f]{64}[\s\S]*https:\/\/sepolia\.arbiscan\.io\/tx\/0x[0-9a-f]{64}/u,
    );
    expect(local.sent).toHaveLength(1);
    expectRelayPaid(local.sent[0]);
    expect(BigInt(local.sent[0]?.nonce ?? 0) >> 248n).toBe(12n);
    expect(await local.chain.rpc("eth_getCode", [address, "latest"])).not.toBe("0x");

    // 5. An owner operation: the root approves it in OAAth and the page submits
    // it once, zero-fee, from the still-unfunded account.
    await click(root, "#owner-prepare");
    await outcome(root, "owner-prepared");
    await capture(root, "owner-prepared");
    popup = await popupFrom(root, "#owner-approve:not([hidden])", "#operation-heading");
    await click(popup, "::-p-text(Approve and sign)");
    await outcome(root, "owner-included");
    expect(local.sent).toHaveLength(2);
    expect(local.sent[1]?.sender.toLowerCase()).toBe(address);
    expect(local.sent[1]?.factory ?? null).toBeNull();
    expectRelayPaid(local.sent[1]);

    // The member: another browser profile opens the invite and joins with a new passkey.
    const device = await browser.createBrowserContext();
    const member = await openDemo(`${demo}/?invite=${address}`, device);
    expect(await text(member, "#join-account")).toBe(address);
    await capture(member, "invitation");
    popup = await popupFrom(member, "#join");
    const authenticator = await addAuthenticator(popup);
    await click(popup, "::-p-text(Add signer)");
    await click(popup, "::-p-text(New passkey)");
    await popup.waitForSelector("::-p-text(This signer has no account yet.)");
    const { credentials } = await authenticator.session.send("WebAuthn.getCredentials", {
      authenticatorId: authenticator.id,
    });
    await click(popup, "::-p-text(Link to an existing account)");
    await popup.type("#link-account", address);
    await click(popup, "::-p-text(Request access)");
    const linkUrl = await (await popup.waitForSelector("#link-url"))?.evaluate(
      (node) => node.textContent ?? "",
    );
    // The root approves the link in the portal.
    const rootPortal = await browser.newPage();
    await rootPortal.setViewport({ width: 390, height: 844 });
    await installWallet(rootPortal);
    await rootPortal.goto(linkUrl ?? "");
    await click(rootPortal, "#wallet-method");
    await click(rootPortal, "::-p-text(E2E Wallet)");
    await click(rootPortal, "::-p-text(Approve and sign)");
    await rootPortal.waitForSelector("::-p-text(Signer added)");
    await click(popup, `button[aria-label='Smart account ${address}, Signer']`);
    await outcome(member, "signed-in");
    expect(await member.$eval("#s-join", (node) => (node as HTMLElement).hidden)).toBe(true);
    expect(await text(member, "#login")).toBe("Sign in again");
    expect(JSON.parse(await text(member, "#identity"))).toMatchObject({
      account: address,
      role: "permission",
    });
    expect(await member.$eval("#s-invite", (node) => (node as HTMLElement).hidden)).toBe(true);

    // The member's Grant waits for the root.
    // Bound to the member's login: no pickers; sending signs the member in.
    popup = await popupFrom(member, "#grant", "#ask-heading");
    await withCredential(popup, credentials);
    await click(popup, "::-p-text(Send request to the owner)");
    await outcome(member, "pending");
    expect(await text(member, "#grant-badge")).toBe("Waiting for owner");
    expect(await member.$eval("#redeem", (node) => node.classList.contains("button-primary"))).toBe(
      true,
    );
    await capture(member, "pending");
    expect(await text(member, "#grant-state")).toContain(`${portal}/requests/`);
    expect(await member.$eval("#redeem", (node) => (node as HTMLElement).hidden)).toBe(false);

    // The root approves from its accounts view with one signature.
    await rootPortal.goto(`${portal}/accounts`);
    await click(rootPortal, "#wallet-method");
    await click(rootPortal, "::-p-text(E2E Wallet)");
    await click(rootPortal, `button[aria-label='Smart account ${address}']`);
    await rootPortal.waitForSelector("#requests-heading");
    const approvals = walletSignatures;
    await click(rootPortal, "button[aria-label='Approve OAAth Demo']");
    await rootPortal.waitForSelector("#requests-heading", { hidden: true });
    expect(walletSignatures).toBe(approvals + 1);
    await rootPortal.close();

    // A reload recreates the SDK; redeemPending yields the Grant.
    await member.reload();
    await outcome(member, "granted");
    expect(await text(member, "#identity-title")).toBe("Saved account · sign in again");
    expect(await text(member, "#account")).toBe(address);

    // The member's relay-paid test call enables its permission and executes.
    await click(member, "#send");
    await outcome(member, "finalized");
    expect(local.sent).toHaveLength(3);
    expectRelayPaid(local.sent[2]);
    expect(BigInt(local.sent[2]?.nonce ?? 0) >> 248n).toBe(12n);
    // Approval was the root's one signature; the member's send asked it nothing.
    expect(walletSignatures).toBe(approvals + 1);

    // A reload observes the stored operation; nothing is resent.
    await member.reload();
    await outcome(member, "finalized");
    expect(local.sent).toHaveLength(3);
    await device.close();

    // The root schedules backend pings: it approves the automation service's
    // own session key in OAAth, and the service sends the first ping, relay-paid.
    // The service's login_hint binds the root and account: no pickers.
    popup = await popupFrom(root, "#automate", "#review-heading");
    expect(await popup.$("#signer-heading")).toBeNull();
    expect(await popup.$("#account-heading")).toBeNull();
    expect(await text(popup, "main")).toContain(`${address.slice(0, 6)}…${address.slice(-4)}`);
    await popup.waitForSelector("::-p-text(Approve and sign):not([disabled])");
    expect(await text(popup, "main")).toContain("0x000000000000000000000000000000000000dead");
    await click(popup, "::-p-text(Approve and sign)");
    await popup.waitForSelector("::-p-text(Authorization authorized)");
    await outcome(root, "automation-finalized", 180_000);
    // One row per ping: the first is included and links its transaction.
    const pings = await root.$$eval("#automation-runs li", (rows) =>
      rows.map((row) => ({
        state: (row as HTMLElement).dataset.state,
        link: row.querySelector("a")?.getAttribute("href") ?? null,
      })),
    );
    expect(pings).toHaveLength(3);
    expect(pings[0]?.state).toBe("included");
    expect(pings[0]?.link).toMatch(/^https:\/\/sepolia\.arbiscan\.io\/tx\/0x[0-9a-f]{64}$/u);
    for (const ping of pings.slice(1))
      expect(["scheduled", "sent", "included"]).toContain(ping.state);
    await capture(root, "automation");
    expect(local.sent).toHaveLength(4);
    expect(local.sent[3]?.sender.toLowerCase()).toBe(address);
    expectRelayPaid(local.sent[3]);
    expect(await local.chain.rpc("eth_getBalance", [address, "latest"])).toBe("0x0");
    await root.close();
  }, 600_000);
});
