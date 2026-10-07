/** Real Chromium reload and cross-tab recovery through packed SDK and relay. */
import { createConsumer, run } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "pending-approval",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server"],
  dependencies: { esbuild: "0.28.1", "puppeteer-core": "25.5.0" },
  files: {
    "browser.mjs": String.raw`
import { createOAAth } from "@oaath/sdk";
const oaath = createOAAth({ approvals: { kind: "service", url: "https://relay.example.test" } });
const connection = await oaath.connect();
globalThis.pendingSmoke = {
  start: () => new Promise(resolve => {
    connection.requestPermission({ chainScope: "all", expiresIn: 1800, perChainOperationLimit: 10,
      permissions: [{ calls: [{ target: "0x" + "44".repeat(20), selectors: ["0xa9059cbb"], valueLimit: "0" }] }],
      onPending: resolve,
    }).catch(() => {});
  }),
  resume: () => connection.resumePendingPermission(),
  withdraw: () => connection.withdrawPendingPermission(),
  close: () => oaath.close(),
};
`,
    "run.mjs": String.raw`
import assert from "node:assert/strict";
import { access } from "node:fs/promises";
import { build } from "esbuild";
import puppeteer from "puppeteer-core";
import { createRelayHandler, createMemoryRelayStore } from "@oaath/server";
const origin = "https://app.example.test";
const relayOrigin = "https://relay.example.test";
const unavailable = async () => { throw new Error("unexpected chain or custody access"); };
const relay = createRelayHandler({
  store: createMemoryRelayStore(),
  authentication: { authenticate: async () => ({ role: "client", clientId: "client-a", subject: "member-a",
    organizationAudience: null, redirectUris: [origin + "/callback"] }) },
  ownerRouting: { resolveOwner: async () => ({ ownerDeviceId: "phone-a", ownerSubject: "owner-a" }) },
  kms: { encrypt: unavailable, decrypt: unavailable }, clock: { now: () => Date.now() },
  bootstrap: { resolve: async () => ({
    application: { applicationId: "app-a", applicationName: "Pending approval proof" },
    context: { version: "oaath.workspace-account-context/v1", workspaceId: "personal-a", workspaceKind: "personal", accountId: "account-a" },
    account: { version: "oaath.kernel-account-profile/v1", kind: "kernel", accountIndex: "0", kernelVersion: "0.4.0", factoryRoute: "kernel_factory",
      entryPoint: { version: "0.9" }, ownerCredential: { version: "oaath.owner-credential-profile/v1", kind: "ecdsa", address: "0x" + "11".repeat(20) } },
    ownerValidator: "0x" + "22".repeat(20), chainIds: [31337],
  }) },
  chains: [{ chainId: 31337, reads: unavailable, observation: unavailable, bundler: unavailable,
    quote: unavailable, submission: unavailable, usage: null, feePayer: null, staticPaymasterConfigurationHash: null }],
});
const bundle = await build({ entryPoints: ["browser.mjs"], bundle: true, write: false, platform: "browser", format: "esm" });
const paths = [];
let browser;
let transportFailed = false;
async function page() {
  const tab = await browser.newPage();
  await tab.setRequestInterception(true);
  tab.on("request", async request => {
    try {
      if (request.url() === origin + "/browser.js") return await request.respond({ status: 200, contentType: "text/javascript", body: bundle.outputFiles[0].text });
      if (request.url() === origin + "/") return await request.respond({ status: 200, contentType: "text/html", body: '<!doctype html><script type="module" src="/browser.js"></script>' });
      if (new URL(request.url()).origin !== relayOrigin) return await request.abort();
      const headers = { "access-control-allow-origin": origin, "access-control-allow-credentials": "true",
        "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "content-type" };
      if (request.method() === "OPTIONS") return await request.respond({ status: 204, headers });
      paths.push(request.method() + " " + new URL(request.url()).pathname);
      const response = await relay(new Request(request.url(), { method: request.method(), headers: request.headers(),
        ...(request.hasPostData() ? { body: await request.fetchPostData() } : {}) }));
      return await request.respond({ status: response.status, headers: { ...Object.fromEntries(response.headers), ...headers }, body: await response.text() });
    } catch { transportFailed = true; await request.abort().catch(() => {}); }
  });
  await tab.goto(origin, { timeout: 10000 });
  await tab.waitForFunction(() => !!globalThis.pendingSmoke, { timeout: 10000 });
  return tab;
}
try {
  let executablePath;
  for (const candidate of [process.env.PUPPETEER_EXECUTABLE_PATH, process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome", "/usr/bin/chromium"].filter(Boolean)) {
    try { await access(candidate); executablePath = candidate; break; } catch {}
  }
  assert.ok(executablePath, "Chrome unavailable");
  browser = await puppeteer.launch({ executablePath, headless: true, args: ["--no-sandbox", "--disable-background-networking"] });
  const first = await page();
  const pending = await first.evaluate(() => globalThis.pendingSmoke.start());
  assert.equal(typeof pending.requestId, "string");
  // No close/settle call: destroy the entire JS realm while its owner decision is pending.
  await first.reload({ timeout: 10000 });
  await first.waitForFunction(() => !!globalThis.pendingSmoke, { timeout: 10000 });
  const second = await page();
  for (const tab of [first, second]) {
    const resumed = await tab.evaluate(() => globalThis.pendingSmoke.resume());
    assert.equal(resumed.requestId, pending.requestId);
    assert.equal(resumed.matchCode, pending.matchCode);
    assert.equal(resumed.status, "pending");
    assert.equal(resumed.grant, null);
  }
  assert.equal((await first.evaluate(() => globalThis.pendingSmoke.withdraw())).status, "withdrawn");
  assert.equal((await second.evaluate(() => globalThis.pendingSmoke.resume())).status, "withdrawn");
  await Promise.all([first, second].map(tab => tab.evaluate(() => globalThis.pendingSmoke.close())));
  assert.equal(paths.filter(path => path === "POST /authorization/requests").length, 1);
  assert.equal(paths.filter(path => path.includes("/consume") || path.endsWith("/claim")).length, 0);
  assert.equal(transportFailed, false);
  console.log("packed Chromium pending approval: page reload, two tabs, original request and match code, withdrawal; zero redemption or chain access");
} finally { await browser?.close(); }
`,
  },
});
try {
  process.stdout.write(
    run(process.execPath, ["run.mjs"], { cwd: consumer.directory, timeout: 90_000 }),
  );
} finally {
  await consumer.cleanup();
}
