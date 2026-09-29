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
 * Four enforced facts:
 *
 *   1. Browser graphs: the transitive import graph of the `@oaath/sdk` and
 *      `@oaath/protocol` root entries reaches no `node:*`, no driver, and no
 *      test-only package.
 *   2. Direction: production edges match the declared table exactly, so
 *      protocol depends on nothing internal, sdk only on protocol, server
 *      composes the SDK through its Kernel execution subpath, and
 *      `@oaath/testing` is never a production dependency of anything.
 *   3. Provenance: every published entry points at built artifacts, never
 *      `src`, and every public package builds those artifacts during `prepack`.
 *      Private packages are never published and are exempt from the provenance
 *      rule.
 *   4. Version-agnostic names: no value or type exported from the
 *      `@oaath/sdk` or `@oaath/sdk/kernel` entry names a Kernel version
 *      (`V33`/`V4`). Versions are optional settings there; version-named
 *      encoders and constants belong on `@oaath/sdk/advanced`.
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
  "@oaath/server": ["@oaath/protocol", "@oaath/sdk"],
  "@oaath/testing": ["@oaath/protocol", "@oaath/sdk", "@oaath/server"],
  "@oaath/contracts": [],
  oaath: ["@oaath/sdk"],
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
    // A private package is never published, so it has no published surface to
    // resolve from src; the provenance rule applies only to released packages.
    if (manifest.private === true) continue;
    for (const field of ["main", "module", "types"]) {
      if (manifest[field] !== undefined && !manifest[field].startsWith("./dist/")) {
        fail(`${name}: ${field} must resolve to dist`);
      }
    }
    if (!(manifest.files ?? []).includes("dist")) {
      fail(`${name}: files must publish dist`);
    }
    if (manifest.scripts?.prepack !== "bun run build") {
      fail(`${name}: prepack must build the published dist`);
    }
    // Source is opt-in for this workspace; ordinary consumers use dist.
    for (const [subpath, entry] of Object.entries(manifest.exports ?? {})) {
      const { "oaath-source": source, ...published } = entry;
      if (source === undefined || Object.keys(published).length === 0) {
        fail(`${name}: exports ${subpath} needs source and published entries`);
      }
      for (const target of Object.values(published)) {
        if (typeof target !== "string" || !target.startsWith("./dist/")) {
          fail(`${name}: exports ${subpath} must resolve to dist for consumers`);
        }
      }
    }
  }
}

/** Every name one entry source exports, after `as` renames, values and types alike. */
async function exportedNames(file) {
  const source = await readFile(file, "utf8");
  const names = [];
  for (const match of source.matchAll(/export\s+(?:type\s+)?\{([^}]*)\}/gu)) {
    for (const item of match[1].split(",")) {
      const name = item
        .trim()
        .replace(/^type\s+/u, "")
        .split(/\s+as\s+/u)
        .at(-1);
      if (name) names.push(name);
    }
  }
  for (const match of source.matchAll(
    /export\s+(?:declare\s+)?(?:async\s+)?(?:function|const|class|interface|type)\s+([A-Za-z0-9_$]+)/gu,
  )) {
    names.push(match[1]);
  }
  return names;
}

async function checkVersionAgnosticEntries(workspace) {
  const sdk = workspace.get("@oaath/sdk");
  for (const entry of ["index.ts", "kernel.ts"]) {
    const names = await exportedNames(new URL(`src/${entry}`, sdk.directory));
    if (names.length < 2) fail(`@oaath/sdk ${entry}: no exports parsed`);
    for (const name of names) {
      if (/V33|V4/u.test(name)) fail(`@oaath/sdk ${entry}: exports version-named ${name}`);
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
await checkVersionAgnosticEntries(workspace);

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
console.log("  versions         @oaath/sdk and /kernel export no V33/V4 name");
