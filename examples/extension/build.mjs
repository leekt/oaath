/**
 * Bundles the extension into dist/: the worker (with @oaath/sdk inlined) plus
 * the static page-world, content-script, and popup files, ready for
 * chrome://extensions "Load unpacked".
 *
 * @author taek <leekt216@gmail.com>
 */
import { copyFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = join(HERE, "dist");

mkdirSync(DIST, { recursive: true });

await build({
  entryPoints: [join(HERE, "worker.js")],
  outfile: join(DIST, "worker.bundle.js"),
  bundle: true,
  format: "esm",
  platform: "browser",
  logLevel: "silent",
});

for (const file of [
  "manifest.json",
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
  copyFileSync(join(HERE, file), join(DIST, file));
}

const size = statSync(join(DIST, "worker.bundle.js")).size;
console.log(`extension built: ${DIST} (worker bundle ${(size / 1024).toFixed(0)} KiB)`);
