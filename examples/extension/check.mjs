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
for (const piece of ["injected.js", "content.js", "popup.html", "popup.js"]) {
  readFileSync(join(HERE, "dist", piece));
}
// The page-world provider announces the EIP-6963 identity dapps discover by.
const injected = readFileSync(join(HERE, "dist", "injected.js"), "utf8");
expect(injected.includes("eip6963:announceProvider"), "injected provider must announce EIP-6963");
expect(injected.includes('rdns: "app.oaath"'), "provider rdns must be app.oaath");

console.log("extension example: ok");
