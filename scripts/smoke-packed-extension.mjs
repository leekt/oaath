/**
 * Real-Chromium proof for the packed MV3 extension.
 *
 * The actual example extension is copied into a clean consumer and its worker
 * is bundled against packed @oaath tarballs. One loopback-only relay and an
 * owned deterministic chain fixture let the page submit exactly once. The
 * test then force-closes Chrome's extension service worker, asks the still-open
 * dapp for status, and requires a distinct worker lifetime to recover the same
 * durable ID without another submission.
 *
 * Evidence limit: the chain is an owned fixture, not Anvil. This proves the
 * packed extension, real IndexedDB, MV3 worker death/wake, durable status, and
 * no-resubmission invariant. Local Anvil execution, retention time advancement,
 * unrelated-log filtering, and the broader origin-isolation matrix have their
 * own focused evidence.
 *
 * @author taek <leekt216@gmail.com>
 */

import { readFile } from "node:fs/promises";
import { assert, createConsumer, run } from "./packed-consumer.mjs";

const EXTENSION_FILES = [
  "build.mjs",
  "content.js",
  "injected.js",
  "manifest.json",
  "popup.html",
  "popup.js",
  "status-presentation.js",
  "status.html",
  "status.js",
  "worker.js",
];

const extensionFiles = Object.fromEntries(
  await Promise.all(
    EXTENSION_FILES.map(async (name) => [
      name,
      await readFile(new URL(`../examples/extension/${name}`, import.meta.url), "utf8"),
    ]),
  ),
);

// The reusable example fixture owns a fixed narrated clock. The extension uses
// its production Date.now clock, so the clean-consumer copy substitutes only
// that one evidence timestamp and otherwise runs the repository-owned fixture.
const fakeChainSource = await readFile(
  new URL("../examples/browser/fake-chain.mjs", import.meta.url),
  "utf8",
);
const chromiumChainSource = fakeChainSource.replace(
  "observedAt: 1_800_000_000",
  "observedAt: Math.floor(Date.now() / 1_000)",
);
assert(chromiumChainSource !== fakeChainSource, "fake chain clock substitution did not apply");

const SMOKE = String.raw`
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { access } from "node:fs/promises";
import { join } from "node:path";
import {
  hashPermissionRequest,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_PERMISSION_DECISION_VERSION,
  parseGrantPolicy,
} from "@oaath/protocol";
import { deriveSessionPolicyProfiles } from "@oaath/sdk/advanced";
import {
  approveKernelPermissionAllChain,
  createKernelRuntime,
  ecdsaKey,
  kernelAllChainCapabilityHash,
  kernelV4Deployment,
  ownerOperator,
  sessionOperator,
} from "@oaath/sdk/kernel";
import { createMemoryRelayStore, createRelayHandler } from "@oaath/server";
import puppeteer from "puppeteer-core";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createFakeChain } from "./fake-chain.mjs";

const CHAIN_ID = 421_614;
const BUNDLE_ID = "chromium-mv3-restart";
const TARGET = "0x" + "44".repeat(20);
const SELECTOR = "0xa9059cbb";
const CALL_DATA = SELECTOR + "0".repeat(128);
const TRANSACTION_HASH = "0x" + "44".repeat(32);
const OWNER_TOKEN = randomUUID();
const OWNER_ACCOUNT = privateKeyToAccount(generatePrivateKey());
const TIMEOUT_MS = 20_000;

function fail(message) {
  throw new Error(message);
}

function expect(fact, message) {
  if (!fact) fail(message);
}

async function bounded(promise, label, milliseconds = TIMEOUT_MS) {
  let timer;
  const expires = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + " timed out")), milliseconds);
  });
  try {
    return await Promise.race([promise, expires]);
  } finally {
    clearTimeout(timer);
  }
}

async function listen(server) {
  await bounded(
    new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    }),
    "loopback server start",
  );
}

async function closeServer(server) {
  if (!server.listening) return;
  server.closeAllConnections?.();
  await bounded(
    new Promise((resolve) => server.close(resolve)),
    "loopback server close",
  );
}

async function chromeExecutable() {
  const configured = [process.env.PUPPETEER_EXECUTABLE_PATH, process.env.CHROME_PATH].filter(
    (value) => typeof value === "string" && value.length > 0,
  );
  const platform =
    process.platform === "darwin"
      ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
      : process.platform === "win32"
        ? [
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
          ]
        : ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium"];
  for (const candidate of [...configured, ...platform]) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Try the next explicit location.
    }
  }
  return fail("Chrome is unavailable; set PUPPETEER_EXECUTABLE_PATH");
}

function workerTargetFor(extensionId) {
  const prefix = "chrome-extension://" + extensionId + "/";
  return (target) => target.type() === "service_worker" && target.url().startsWith(prefix);
}

function destroyedTarget(browser, target) {
  if (!browser.targets().includes(target)) return Promise.resolve();
  return bounded(
    new Promise((resolve) => {
      const listener = (destroyed) => {
        if (destroyed !== target) return;
        browser.off("targetdestroyed", listener);
        resolve();
      };
      browser.on("targetdestroyed", listener);
    }),
    "MV3 worker termination",
  );
}

const chain = createFakeChain(CHAIN_ID);
const relayStore = createMemoryRelayStore();
const counts = { approvals: 0, observations: 0, submissions: 0 };
let relay = null;
let approveRequest = null;
let serviceOrigin = null;

const server = createServer(async (incoming, outgoing) => {
  try {
    const requestUrl = new URL(incoming.url ?? "/", "http://127.0.0.1");
    if (requestUrl.pathname === "/app") {
      outgoing.writeHead(200, {
        "cache-control": "no-store",
        "content-type": "text/html; charset=utf-8",
      });
      outgoing.end(
        "<!doctype html><html><head><meta charset=utf-8><title>OAAth MV3 smoke</title></head>" +
          "<body><main id=ready>ready</main></body></html>",
      );
      return;
    }
    if (relay === null || serviceOrigin === null) fail("relay is not ready");
    const chunks = [];
    for await (const chunk of incoming) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    const headers = new Headers();
    for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
      const name = incoming.rawHeaders[index];
      const value = incoming.rawHeaders[index + 1];
      if (name !== undefined && value !== undefined) headers.append(name, value);
    }
    const request = new Request(serviceOrigin + requestUrl.pathname + requestUrl.search, {
      method: incoming.method,
      headers,
      ...(body.length === 0 ? {} : { body }),
    });
    const response = await relay(request);
    if (
      request.method === "POST" &&
      requestUrl.pathname === "/authorization/requests" &&
      response.status === 201
    ) {
      const created = await response.clone().json();
      if (typeof created.requestId !== "string" || approveRequest === null) {
        fail("authorization request was not capturable");
      }
      await approveRequest(created.requestId);
    }
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    outgoing.writeHead(500, { "content-type": "application/json" });
    outgoing.end('{"error":{"code":"smoke_adapter_failed"}}');
  }
});

let browser = null;
try {
  await import("./build.mjs");
  await listen(server);
  const address = server.address();
  if (address === null || typeof address === "string") fail("loopback server has no port");
  serviceOrigin = "http://127.0.0.1:" + address.port;
  const redirectUri = serviceOrigin + "/callback";

  const accountProfile = Object.freeze({
    version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "kernel_factory",
    entryPoint: Object.freeze({ version: "0.7" }),
    ownerCredential: Object.freeze({
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: OWNER_ACCOUNT.address.toLowerCase(),
    }),
  });

  const chainPort = {
    chainId: CHAIN_ID,
    reads: (request) => chain.capability.reads.read(request),
    async observation(request) {
      counts.observations += 1;
      return chain.capability.observation.read(request);
    },
    bundler: (request) => chain.capability.bundler.probe(request),
    quote: (request) => chain.capability.quote(request),
    async submission(request) {
      counts.submissions += 1;
      if (counts.submissions !== 1) fail("a second submission reached the chain fixture");
      const session = await chain.capability.submission.open(request);
      try {
        return await session.send();
      } finally {
        await session.close();
      }
    },
    usage:
      chain.capability.usage === null
        ? null
        : (request) => chain.capability.usage(request),
    feePayer: chain.capability.feePayer,
    staticPaymasterConfigurationHash: chain.capability.staticPaymasterConfigurationHash,
  };

  relay = createRelayHandler({
    store: relayStore,
    authentication: {
      async authenticate(request) {
        const header = request.headers.get("authorization") ?? "";
        if (header === "Bearer " + OWNER_TOKEN) {
          return {
            role: "owner",
            clientId: "owner-console",
            subject: "chromium-subject",
            redirectUris: [],
          };
        }
        return {
          role: "client",
          clientId: "chromium-client",
          subject: "chromium-subject",
          redirectUris: [redirectUri],
        };
      },
    },
    kms: {
      async encrypt(plaintext) {
        return "chromium-smoke-kms:v1:" + Buffer.from(plaintext, "utf8").toString("base64");
      },
      async decrypt(reference) {
        const prefix = "chromium-smoke-kms:v1:";
        if (!reference.startsWith(prefix)) fail("unknown smoke ciphertext");
        return Buffer.from(reference.slice(prefix.length), "base64").toString("utf8");
      },
    },
    clock: { now: () => Date.now() },
    bootstrap: {
      application: {
        applicationId: "chromium-app",
        applicationName: "OAAth Chromium Smoke",
        clientId: "chromium-client",
        redirectUris: [redirectUri],
      },
      userHandle: "chromium-user",
      account: accountProfile,
      ownerValidator: chain.validator,
    },
    chains: [chainPort],
  });

  const ownerFetch = async (path, init) => {
    if (relay === null || serviceOrigin === null) fail("relay is unavailable");
    const headers = new Headers(init?.headers);
    headers.set("authorization", "Bearer " + OWNER_TOKEN);
    return (
      await relay(
        new Request(serviceOrigin + path, {
          ...init,
          headers,
        }),
      )
    ).json();
  };

  approveRequest = async (requestId) => {
    counts.approvals += 1;
    if (counts.approvals !== 1) fail("owner approval ran more than once");
    const state = await ownerFetch("/authorization/requests/" + requestId);
    if (typeof state.requestedScope !== "string") fail("owner review scope is unavailable");
    const scope = JSON.parse(state.requestedScope);
    const ownerKey = ecdsaKey({ account: OWNER_ACCOUNT, validator: chain.validator });
    const deployment = kernelV4Deployment(CHAIN_ID);
    const ownerRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({ key: ownerKey }),
      reads: chain.capability.reads,
    });
    const descriptor = await ownerRuntime.bindAccount({
      accountIndex: "0",
      initialPackages: [...ownerRuntime.packages],
    });
    const sessionRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: ecdsaKey({
          account: { address: scope.operatorCredential.address, sign: async () => "0x" },
          validator: chain.validator,
        }),
        policies: deriveSessionPolicyProfiles(parseGrantPolicy(scope.policy)),
      }),
      reads: chain.capability.reads,
    });
    const installApproval = await approveKernelPermissionAllChain({
      owner: ownerKey,
      account: descriptor.account,
      installNonce: "0",
      packages: [...sessionRuntime.packages],
    });
    const decided = await ownerFetch("/authorization/requests/" + requestId + "/decision", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        outcome: "approved",
        artifact: JSON.stringify({
          version: OAATH_PERMISSION_DECISION_VERSION,
          kind: "approve",
          requestId,
          requestHash: hashPermissionRequest({ ...scope, requestId }),
          decidedAt: Math.floor(Date.now() / 1_000),
          approvedPolicy: scope.policy,
          capabilityHash: kernelAllChainCapabilityHash(installApproval),
          installApproval,
        }),
      }),
    });
    if (typeof decided.code !== "string") fail("owner decision was not accepted");
  };

  const executablePath = await chromeExecutable();
  browser = await puppeteer.launch({
    browser: "chrome",
    executablePath,
    headless: false,
    pipe: true,
    enableExtensions: [join(process.cwd(), "dist")],
    userDataDir: join(process.cwd(), "chrome-profile"),
    args: [
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-domain-reliability",
      "--disable-sync",
      "--metrics-recording-only",
      "--no-default-browser-check",
      "--no-first-run",
      "--password-store=basic",
      "--use-mock-keychain",
    ],
  });

  const installedWorkerTarget = await browser.waitForTarget(
    (target) => target.type() === "service_worker" && target.url().endsWith("/worker.bundle.js"),
    { timeout: TIMEOUT_MS },
  );
  const extensionId = new URL(installedWorkerTarget.url()).hostname;
  if (!/^[a-p]{32}$/u.test(extensionId)) fail("the OAAth extension ID is unavailable");

  const dapp = await browser.newPage();
  await bounded(
    dapp.goto(serviceOrigin + "/app", { waitUntil: "domcontentloaded" }),
    "dapp navigation",
  );
  const discovered = await dapp.evaluate(() =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("OAAth provider was not announced")), 5_000);
      const listener = (event) => {
        if (event.detail?.info?.rdns !== "app.oaath") return;
        clearTimeout(timer);
        window.removeEventListener("eip6963:announceProvider", listener);
        window.__oaathProvider = event.detail.provider;
        resolve(event.detail.info.rdns);
      };
      window.addEventListener("eip6963:announceProvider", listener);
      window.dispatchEvent(new Event("eip6963:requestProvider"));
    }),
  );
  expect(discovered === "app.oaath", "the dapp discovered another provider");

  const popup = await browser.newPage();
  await bounded(
    popup.goto("chrome-extension://" + extensionId + "/popup.html", {
      waitUntil: "domcontentloaded",
    }),
    "extension page navigation",
  );
  const paired = await popup.evaluate(
    async (input) => {
      await chrome.storage.local.set({ url: input.url, chain: input.chain });
      return chrome.runtime.sendMessage({
        type: "popup",
        command: "pair",
        origin: input.origin,
        scope: {
          target: input.target,
          selector: input.selector,
          valueLimit: "1000",
          expiresIn: 1_800,
          perChainOperationLimit: 10,
        },
      });
    },
    {
      url: serviceOrigin,
      chain: CHAIN_ID,
      origin: serviceOrigin,
      target: TARGET,
      selector: SELECTOR,
    },
  );
  if (paired?.ok !== true || paired.result?.state !== "active") {
    fail("the extension did not pair the dapp");
  }
  const account = paired.result.account;
  if (typeof account !== "string") fail("the paired account is unavailable");
  await popup.close();

  const request = {
    version: "2.0.0",
    id: BUNDLE_ID,
    from: account,
    chainId: "0x" + CHAIN_ID.toString(16),
    atomicRequired: true,
    calls: [{ to: TARGET, data: CALL_DATA, value: "0x5" }],
  };
  const sent = await dapp.evaluate(
    (bundle) => window.__oaathProvider.request({ method: "wallet_sendCalls", params: [bundle] }),
    request,
  );
  expect(sent?.id === BUNDLE_ID, "wallet_sendCalls returned another ID");
  expect(counts.submissions === 1, "wallet_sendCalls did not submit exactly once");
  expect(chain.sends.length === 1, "the chain retained another submission count");

  const targetPredicate = workerTargetFor(extensionId);
  const firstWorkerTarget = await browser.waitForTarget(targetPredicate, { timeout: TIMEOUT_MS });
  const firstWorker = await firstWorkerTarget.worker();
  if (firstWorker === null) fail("the first MV3 worker is unavailable");
  const destroyed = destroyedTarget(browser, firstWorkerTarget);
  await firstWorker.close();
  await destroyed;
  expect(!browser.targets().includes(firstWorkerTarget), "the first MV3 worker survived close");

  const observationsBeforeRecovery = counts.observations;
  const nextWorkerTarget = browser.waitForTarget(
    (target) => target !== firstWorkerTarget && targetPredicate(target),
    { timeout: TIMEOUT_MS },
  );
  const statusPromise = dapp.evaluate((id) =>
    window.__oaathProvider.request({ method: "wallet_getCallsStatus", params: [id] }),
  BUNDLE_ID);
  const secondWorkerTarget = await nextWorkerTarget;
  const status = await statusPromise;
  expect(secondWorkerTarget !== firstWorkerTarget, "status reused the terminated worker target");
  expect(status?.id === BUNDLE_ID, "recovered status returned another ID");
  expect(status?.status === 200, "recovered status was not confirmed");
  expect(status?.atomic === true, "recovered status lost atomic execution");
  expect(
    status?.receipts?.[0]?.transactionHash === TRANSACTION_HASH,
    "recovered status returned another receipt",
  );
  expect(
    counts.observations > observationsBeforeRecovery,
    "recovered status did not observe the exact operation",
  );
  expect(counts.submissions === 1, "status recovery submitted another operation");
  expect(chain.sends.length === 1, "status recovery changed the retained submission");

  const duplicate = await dapp.evaluate(async (bundle) => {
    try {
      await window.__oaathProvider.request({ method: "wallet_sendCalls", params: [bundle] });
      return { ok: true };
    } catch (error) {
      return { ok: false, code: error?.code };
    }
  }, request);
  expect(duplicate.ok === false && duplicate.code === 5720, "duplicate ID did not return 5720");
  expect(counts.submissions === 1, "duplicate ID submitted another operation");
  expect(chain.sends.length === 1, "duplicate ID changed exact submission history");
  expect(counts.approvals === 1, "worker recovery requested owner approval again");

  process.stdout.write(
    "\n" +
      JSON.stringify({
        id: BUNDLE_ID,
        status: status.status,
        submissions: counts.submissions,
        observations: counts.observations,
        workerRestarted: true,
        duplicateCode: duplicate.code,
      }),
  );
} finally {
  await browser?.close().catch(() => undefined);
  await closeServer(server).catch(() => undefined);
  await relayStore.close().catch(() => undefined);
  chain.stop();
}
`;

let consumer;
try {
  consumer = await createConsumer({
    label: "chromium-extension",
    packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server"],
    dependencies: {
      esbuild: "0.28.1",
      "puppeteer-core": "25.5.0",
      viem: "2.55.8",
    },
    files: {
      ...extensionFiles,
      "fake-chain.mjs": chromiumChainSource,
      "smoke.mjs": SMOKE,
    },
  });
  const output = run(process.execPath, ["smoke.mjs"], {
    cwd: consumer.directory,
    timeout: 120_000,
  });
  const reportLine = output
    .trim()
    .split("\n")
    .findLast((line) => line.startsWith("{"));
  if (reportLine === undefined) throw new Error("Chromium smoke returned no report");
  const report = JSON.parse(reportLine);
  assert(report.workerRestarted === true, "Chromium did not restart the MV3 worker");
  assert(report.status === 200, "Chromium did not recover confirmed status");
  assert(report.submissions === 1, "Chromium recovery resubmitted");
  assert(report.duplicateCode === 5720, "Chromium duplicate ID did not return 5720");
  console.log("packed Chromium MV3 extension smoke: ok");
  console.log(`  bundle           ${report.id}, status ${report.status}`);
  console.log(
    `  worker restart   forced death, distinct wake, ${report.observations} observations`,
  );
  console.log(
    `  submission       ${report.submissions}; duplicate refused with ${report.duplicateCode}`,
  );
} catch (error) {
  console.error("packed Chromium MV3 extension smoke: FAILED");
  console.error(error instanceof Error ? error.message : "unknown failure");
  process.exitCode = 1;
} finally {
  await consumer?.cleanup();
}
