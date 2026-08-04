/**
 * Owns: no Node, PostgreSQL, or native surface may leak into a browser export
 * graph, and the published dependency direction stays one-way.
 *
 * Repo-level because both facts are cross-package. `@oaath/sdk`'s root entry
 * imports `@oaath/protocol`, so a `node:` or `pg` import added inside protocol
 * would reach every browser bundle without any single package's own boundary
 * test noticing. This walker follows workspace edges into the imported
 * package's source instead of stopping at the bare specifier.
 *
 * Three enforced facts:
 *
 *   1. Browser graphs: the transitive import graph of the `@oaath/sdk` and
 *      `@oaath/protocol` root entries reaches no `node:*`, no driver, and no
 *      test-only package.
 *   2. Direction: production edges match the declared table exactly, so
 *      protocol depends on nothing internal, sdk only on protocol, and
 *      `@oaath/testing` is never a production dependency of anything.
 *   3. Provenance: no published entry points at `src`, so a consumer resolves
 *      built artifacts only.
 *
 * `@oaath/server`'s own entries are owned by `packages/server/test/package.test.ts`;
 * this gate covers the graphs that cross a package boundary.
 *
 * @author taek <leekt216@gmail.com>
 */

import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path/posix";

const PACKAGES = new URL("../packages/", import.meta.url);

/** Browser graphs may not reach these. */
const FORBIDDEN = [
  { match: (target) => target.startsWith("node:"), why: "Node builtin" },
  { match: (target) => target === "pg" || target.startsWith("pg/"), why: "PostgreSQL driver" },
  {
    match: (target) => target === "postgres" || target.startsWith("postgres/"),
    why: "PostgreSQL driver",
  },
  { match: (target) => target === "@oaath/server/postgres", why: "Node-only PostgreSQL subpath" },
  { match: (target) => target.startsWith("@oaath/testing"), why: "test-only package" },
];

/**
 * Exact production dependency direction. A package may hold no internal
 * production dependency outside its entry here, and no entry may be widened
 * without changing this table.
 */
const DIRECTION = {
  "@oaath/protocol": [],
  "@oaath/sdk": ["@oaath/protocol"],
  "@oaath/server": ["@oaath/protocol"],
  "@oaath/testing": ["@oaath/protocol", "@oaath/sdk"],
};

/** Production groups only: a devDependency never reaches a consumer. */
const PRODUCTION_GROUPS = ["dependencies", "peerDependencies", "optionalDependencies"];

const failures = [];

function fail(message) {
  failures.push(message);
}

async function readManifests() {
  const entries = await readdir(PACKAGES, { withFileTypes: true });
  const found = new Map();
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const directory = new URL(`${entry.name}/`, PACKAGES);
    const manifest = JSON.parse(await readFile(new URL("package.json", directory), "utf8"));
    found.set(manifest.name, { manifest, directory });
  }
  return found;
}

/**
 * Resolves an `@oaath/*` specifier to its source file inside the workspace, so
 * the walk crosses package boundaries the way a bundler does.
 */
function internalSource(specifier, workspace) {
  const parts = specifier.split("/");
  const name = `${parts[0]}/${parts[1]}`;
  const found = workspace.get(name);
  if (found === undefined) return null;
  const subpath = parts.slice(2).join("/");
  const file = subpath === "" ? "index.ts" : `${subpath.replace(/\.js$/u, "")}.ts`;
  return { package: name, file, root: new URL("src/", found.directory) };
}

/**
 * Every module specifier in one source file: `import`/`export ... from`,
 * side-effect `import`, and dynamic `import()`. Each pattern requires the
 * separator a statement actually has, so a string literal like `"from", "x"` in
 * a field list is not mistaken for an import.
 */
const SPECIFIER_PATTERNS = [
  /\bfrom\s+"([^"]+)"/gu,
  /^\s*import\s+"([^"]+)"/gmu,
  /\bimport\s*\(\s*"([^"]+)"/gu,
];

function specifiers(source) {
  const found = [];
  for (const pattern of SPECIFIER_PATTERNS) {
    for (const match of source.matchAll(pattern)) {
      if (match[1] !== undefined) found.push(match[1]);
    }
  }
  return found;
}

/**
 * Transitive import graph from one package entry, following relative imports
 * inside a package and workspace edges between packages.
 */
async function entryGraph(entry, workspace) {
  const modules = new Set();
  const external = new Set();
  const start = internalSource(entry, workspace);
  if (start === null) throw new Error(`unknown workspace package: ${entry}`);
  const queue = [start];
  while (queue.length > 0) {
    const current = queue.pop();
    if (current === undefined) continue;
    const id = `${current.package}:${current.file}`;
    if (modules.has(id)) continue;
    modules.add(id);
    const source = await readFile(new URL(current.file, current.root), "utf8");
    for (const target of specifiers(source)) {
      if (target.startsWith(".")) {
        queue.push({
          ...current,
          file: join(dirname(current.file), target.replace(/\.js$/u, ".ts")),
        });
        continue;
      }
      external.add(target);
      if (!target.startsWith("@oaath/")) continue;
      const internal = internalSource(target, workspace);
      // An unknown @oaath specifier is a broken edge, not an allowed external.
      if (internal === null) fail(`${entry}: imports unresolvable workspace edge ${target}`);
      else queue.push(internal);
    }
  }
  return { modules, external };
}

async function checkBrowserGraph(entry, workspace) {
  const graph = await entryGraph(entry, workspace);
  for (const target of [...graph.external].sort()) {
    for (const rule of FORBIDDEN) {
      if (rule.match(target)) fail(`${entry}: browser graph reaches ${target} (${rule.why})`);
    }
  }
  // A collapsed graph would satisfy every negative assertion above vacuously.
  if (graph.modules.size < 5) {
    fail(`${entry}: walked only ${graph.modules.size} modules; the graph did not resolve`);
  }
  return graph;
}

function checkDirection(workspace) {
  for (const [name, { manifest }] of workspace) {
    const allowed = DIRECTION[name];
    if (allowed === undefined) {
      fail(`${name}: no declared dependency direction; add it to DIRECTION`);
      continue;
    }
    for (const group of PRODUCTION_GROUPS) {
      for (const dependency of Object.keys(manifest[group] ?? {})) {
        if (!dependency.startsWith("@oaath/")) continue;
        if (!allowed.includes(dependency)) {
          fail(`${name}: ${group} must not depend on ${dependency}`);
        }
      }
    }
  }
}

function checkPublishedEntries(workspace) {
  for (const [name, { manifest }] of workspace) {
    const published = manifest.publishConfig;
    if (published === undefined) {
      fail(`${name}: no publishConfig; published entries would resolve to source`);
      continue;
    }
    if (JSON.stringify(published).includes("./src/")) {
      fail(`${name}: publishConfig points at src; a consumer would resolve source`);
    }
    if (!(manifest.files ?? []).includes("dist")) {
      fail(`${name}: files must publish dist`);
    }
    // Every source entry needs a published counterpart, or the subpath 404s.
    for (const subpath of Object.keys(manifest.exports ?? {})) {
      if (published.exports?.[subpath] === undefined) {
        fail(`${name}: exports ${subpath} has no publishConfig counterpart`);
      }
    }
  }
}

function externals(graph) {
  return [...graph.external].sort().join(", ");
}

const workspace = await readManifests();
const sdk = await checkBrowserGraph("@oaath/sdk", workspace);
const protocol = await checkBrowserGraph("@oaath/protocol", workspace);
checkDirection(workspace);
checkPublishedEntries(workspace);

if (failures.length > 0) {
  console.error("check-public-surface: FAILED");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log("check-public-surface: ok");
console.log(`  @oaath/sdk       ${sdk.modules.size} modules; externals: ${externals(sdk)}`);
console.log(
  `  @oaath/protocol  ${protocol.modules.size} modules; externals: ${externals(protocol)}`,
);
console.log(`  direction        ${Object.keys(DIRECTION).length} packages, production edges only`);
console.log("  provenance       every published entry resolves dist");
