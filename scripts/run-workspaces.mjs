/**
 * Owns: running one package script across workspaces in runtime-dependency
 * order (build, and the pack/publish scripts whose prepack builds).
 *
 * `bun run --workspaces` and `bun run --filter` start scripts concurrently once
 * the dev graph has a cycle (the SDK's tests depend on `@oaath/server` and
 * `@oaath/testing`, which depend on the SDK), so a dependent can bundle a
 * `dist` that is still being replaced. Only runtime `dependencies` and
 * `peerDependencies` order scripts here; each runs after its dependencies
 * finish.
 *
 * Usage: `node scripts/run-workspaces.mjs <script> [package-name...]`; no names
 * runs every workspace package that defines the script.
 *
 * @author taek <leekt216@gmail.com>
 */

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));

function workspaces() {
  const packages = new Map();
  for (const parent of ["packages", "examples"]) {
    const base = join(ROOT, parent);
    const directories =
      parent === "examples"
        ? [base]
        : readdirSync(base, { withFileTypes: true })
            .filter((entry) => entry.isDirectory())
            .map((entry) => join(base, entry.name));
    for (const directory of directories) {
      let manifest;
      try {
        manifest = JSON.parse(readFileSync(join(directory, "package.json"), "utf8"));
      } catch {
        continue;
      }
      packages.set(manifest.name, { directory, manifest });
    }
  }
  return packages;
}

/** Topological order of the named packages (default: all defining the script). */
export function scriptOrder(script, names) {
  const packages = workspaces();
  const selected = names?.length
    ? names
    : [...packages.keys()].filter((name) => packages.get(name).manifest.scripts?.[script]);
  const order = [];
  const state = new Map();
  function visit(name, path) {
    const entry = packages.get(name);
    if (!entry) throw new Error(`Unknown workspace package: ${name}`);
    if (state.get(name) === "done") return;
    if (state.get(name) === "visiting")
      throw new Error(`Runtime dependency cycle: ${[...path, name].join(" -> ")}`);
    state.set(name, "visiting");
    const { dependencies = {}, peerDependencies = {} } = entry.manifest;
    for (const dependency of Object.keys({ ...dependencies, ...peerDependencies })) {
      if (packages.has(dependency) && selected.includes(dependency))
        visit(dependency, [...path, name]);
    }
    state.set(name, "done");
    order.push(name);
  }
  for (const name of selected) visit(name, []);
  return order.filter((name) => packages.get(name).manifest.scripts?.[script]);
}

/** Runs the script in the named packages sequentially in dependency order, failing on the first error. */
export function runWorkspaceScript(script, names, options = {}) {
  for (const name of scriptOrder(script, names)) {
    const result = spawnSync("bun", ["run", "--filter", name, script], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: options.stdio ?? "inherit",
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(
        `${name} ${script} exited ${result.status}\n${result.stdout ?? ""}${result.stderr ?? ""}`,
      );
    }
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [script, ...names] = process.argv.slice(2);
  if (!script) throw new Error("Usage: run-workspaces.mjs <script> [package-name...]");
  runWorkspaceScript(script, names);
}
