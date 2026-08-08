/**
 * The extension's documentation gate: the bundle builds from the current
 * workspace and ships a coherent MV3 artifact. Chrome itself is the only
 * runtime for the worker, so this proves buildability and shape, not runtime
 * behavior — the provider surface it exposes is `@oaath/sdk/viem`, which the
 * SDK's own suite covers.
 *
 * @author taek <leekt216@gmail.com>
 */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { formatWalletCallStatus, showWalletCallStatus } from "./status-presentation.js";
import {
  confirmWalletCalls,
  decideWalletCallConfirmation,
  formatWalletCallConfirmation,
  rejectClosedWalletCallConfirmation,
} from "./transaction-confirmation-presentation.js";

const HERE = dirname(fileURLToPath(import.meta.url));

function expect(fact, message) {
  if (!fact) {
    console.error(`extension check failed: ${message}`);
    process.exit(1);
  }
}

const built = spawnSync(process.execPath, [join(HERE, "build.mjs")], { stdio: "inherit" });
expect(built.status === 0, "build.mjs failed");

const manifest = JSON.parse(readFileSync(join(HERE, "dist", "manifest.json"), "utf8"));
expect(manifest.manifest_version === 3, "manifest must be MV3");
expect(manifest.background.service_worker === "worker.bundle.js", "worker entry mismatch");
// Chrome injects the page-world provider itself, so a page CSP cannot block
// it the way it could a DOM-appended chrome-extension:// script element.
const pageWorld = manifest.content_scripts.find((entry) => entry.js.includes("injected.js"));
expect(pageWorld?.world === "MAIN", "page-world provider must be a MAIN-world content script");
expect(
  manifest.content_scripts.some(
    (entry) => entry.js.includes("content.js") && entry.world !== "MAIN",
  ),
  "the bridge must stay in the isolated world",
);

const bundle = readFileSync(join(HERE, "dist", "worker.bundle.js"), "utf8");
expect(!/\brequire\(/u.test(bundle), "worker bundle must be pure ESM");
expect(!/node:[a-z]/u.test(bundle), "worker bundle must not import node builtins");
for (const piece of [
  "injected.js",
  "content.js",
  "popup.html",
  "popup.js",
  "status.html",
  "status.js",
  "status-presentation.js",
  "transaction-confirmation.html",
  "transaction-confirmation.js",
  "transaction-confirmation-presentation.js",
]) {
  readFileSync(join(HERE, "dist", piece));
}
expect(
  formatWalletCallStatus({
    origin: "https://example.test",
    status: { id: "bundle-1", chainId: "0x1", atomic: true, status: 100 },
  }).includes("status   100 pending"),
  "status page must render pending wallet calls",
);
expect(
  formatWalletCallStatus({
    origin: "https://example.test",
    status: {
      id: "bundle-2",
      chainId: "0x1",
      atomic: true,
      status: 200,
      receipts: [{ transactionHash: "0x1234", blockNumber: "0x2", status: "0x1" }],
    },
  }).includes("tx       0x1234"),
  "status page must render confirmed transaction evidence",
);
const presentationEvents = [];
await showWalletCallStatus(
  {
    runtime: { getURL: (path) => `chrome-extension://oaath/${path}` },
    storage: {
      session: {
        async set(value) {
          presentationEvents.push({ kind: "stored", value });
        },
        async remove() {
          presentationEvents.push({ kind: "removed" });
        },
      },
    },
    tabs: {
      async create(value) {
        presentationEvents.push({ kind: "opened", value });
      },
    },
  },
  "https://example.test",
  { id: "bundle-3", chainId: "0x1", atomic: true, status: 100 },
);
expect(presentationEvents.length === 2, "status presentation must store then open exactly once");
expect(presentationEvents[0]?.kind === "stored", "status presentation must store before opening");
expect(presentationEvents[1]?.kind === "opened", "status presentation must open its status page");
expect(
  presentationEvents[1]?.value?.url.startsWith("chrome-extension://oaath/status.html#"),
  "status presentation must open the extension-owned status page",
);

const confirmationRecords = new Map();
const confirmationEvents = [];
let nextConfirmationTab = 41;
const confirmationExtension = {
  runtime: { getURL: (path) => `chrome-extension://oaath/${path}` },
  storage: {
    session: {
      async set(value) {
        for (const [key, record] of Object.entries(value)) confirmationRecords.set(key, record);
        confirmationEvents.push({ kind: "stored", value });
      },
      async get(key) {
        return confirmationRecords.has(key) ? { [key]: confirmationRecords.get(key) } : {};
      },
      async remove(key) {
        confirmationRecords.delete(key);
        confirmationEvents.push({ kind: "removed", key });
      },
    },
  },
  tabs: {
    async create(value) {
      const tab = { id: nextConfirmationTab };
      nextConfirmationTab += 1;
      confirmationEvents.push({ kind: "opened", value, tab });
      return tab;
    },
  },
};
const exactCalls = Object.freeze({
  account: `0x${"11".repeat(20)}`,
  chainId: "0x1",
  calls: Object.freeze([
    Object.freeze({ target: `0x${"44".repeat(20)}`, value: "0", data: "0xabcd" }),
  ]),
});
const approval = confirmWalletCalls(confirmationExtension, "https://example.test", exactCalls);
await Promise.resolve();
await Promise.resolve();
const approvalOpen = confirmationEvents.find((event) => event.kind === "opened");
const approvalToken = decodeURIComponent(approvalOpen?.value?.url.split("#")[1] ?? "");
const approvalKey = `wallet-call-confirmation:${approvalToken}`;
const approvalRecord = confirmationRecords.get(approvalKey);
expect(approvalRecord?.origin === "https://example.test", "confirmation must bind page origin");
expect(Object.isFrozen(approvalRecord), "confirmation display must be frozen");
expect(Object.isFrozen(approvalRecord?.calls), "confirmation calls must be frozen");
expect(Object.isFrozen(approvalRecord?.calls?.[0]), "each confirmation call must be frozen");
expect(
  Object.keys(approvalRecord ?? {}).join(",") === "origin,account,chainId,calls",
  "session storage must contain public display fields only",
);
expect(
  formatWalletCallConfirmation(approvalRecord).includes(`target   0x${"44".repeat(20)}`),
  "confirmation page must render the exact ordered call",
);
expect(
  await decideWalletCallConfirmation(confirmationExtension, approvalToken, "approved"),
  "the pending approval must settle",
);
expect((await approval) === "approved", "the presenter must return the exact approval");
expect(!confirmationRecords.has(approvalKey), "settlement must remove public display state");
expect(
  !(await decideWalletCallConfirmation(confirmationExtension, approvalToken, "approved")),
  "a decision token must be one-use",
);

const rejection = confirmWalletCalls(confirmationExtension, "https://example.test", exactCalls);
await Promise.resolve();
await Promise.resolve();
expect(
  await rejectClosedWalletCallConfirmation(confirmationExtension, 42),
  "closing the confirmation tab must find its pending decision",
);
expect((await rejection) === "rejected", "closing the confirmation tab must reject");

const orphanToken = "11111111-1111-4111-8111-111111111111";
const orphanKey = `wallet-call-confirmation:${orphanToken}`;
await confirmationExtension.storage.session.set({ [orphanKey]: approvalRecord });
expect(
  !(await decideWalletCallConfirmation(confirmationExtension, orphanToken, "approved")),
  "a restarted worker must not recover approval authority from display state",
);
expect(!confirmationRecords.has(orphanKey), "an orphaned display must be removed");
// The page-world provider announces the EIP-6963 identity dapps discover by.
const injected = readFileSync(join(HERE, "dist", "injected.js"), "utf8");
expect(injected.includes("eip6963:announceProvider"), "injected provider must announce EIP-6963");
expect(injected.includes('rdns: "app.oaath"'), "provider rdns must be app.oaath");

console.log("extension example: ok");
