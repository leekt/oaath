/**
 * Runs every example and fails if any of them does.
 *
 * This is a documentation gate, not release evidence: it proves the examples in
 * this repository still run against the current workspace. `pnpm smoke` owns the
 * public-surface claim, because it consumes packed tarballs instead of the
 * workspace. This is deliberately not wired into CI — see ./README.md.
 *
 * @author taek <leekt216@gmail.com>
 */

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const HOOK = fileURLToPath(new URL("./support/workspace-typescript.mjs", import.meta.url));

/** Probed here rather than imported: this file runs without the resolve hook. */
function anvilAvailable() {
  const probe = spawnSync(process.env.ANVIL_PATH ?? "anvil", ["--version"], { stdio: "ignore" });
  return probe.error === undefined && probe.status === 0;
}

const examples = [
  { label: "browser", script: "browser/run.mjs", env: {} },
  { label: "server", script: "server/run.mjs", env: { OAATH_SMOKE: "1", OAATH_PORT: "0" } },
];

if (anvilAvailable()) {
  examples.push({ label: "all-chain", script: "all-chain/run.mjs", env: {} });
} else {
  console.log("examples:check: skipping all-chain, Anvil is not installed");
}

const failures = [];
for (const example of examples) {
  console.log(`\n=== ${example.label} ===`);
  const result = spawnSync("node", ["--import", HOOK, example.script], {
    cwd: HERE,
    stdio: "inherit",
    env: { ...process.env, ...example.env },
  });
  if (result.status !== 0) failures.push(example.label);
}

console.log("");
if (failures.length === 0) {
  console.log(`examples:check: ok (${examples.map((example) => example.label).join(", ")})`);
} else {
  console.error(`examples:check: FAILED (${failures.join(", ")})`);
  process.exitCode = 1;
}
