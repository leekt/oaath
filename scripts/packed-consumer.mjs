/**
 * Owns: building, packing, and installing workspace tarballs into a clean
 * consumer outside the workspace.
 *
 * Shared by `smoke-packed-browser.mjs` and `smoke-packed-server.mjs`. A consumer
 * lives in a fresh temporary directory with its own `node_modules`, installed by
 * `npm` from tarballs only, so nothing resolves through the Bun workspace link
 * farm and no `src` path is reachable. `bun pm pack` rewrites `workspace:*` to the
 * literal version, which is unpublished, so every internal edge is pinned back
 * to its tarball through npm `overrides`.
 *
 * @author taek <leekt216@gmail.com>
 */

import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runWorkspaceScript } from "./run-workspaces.mjs";

export const WORKSPACE_ROOT = fileURLToPath(new URL("../", import.meta.url));

/** Runs a command and returns its captured stdout, failing closed on any error. */
export function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} exited ${result.status}\n${result.stdout ?? ""}${result.stderr ?? ""}`,
    );
  }
  return result.stdout ?? "";
}

/**
 * Builds and packs the named workspace packages, returning each tarball path.
 * The build runs here so a smoke can never pass against a stale `dist`.
 */
export async function packWorkspacePackages(names, destination) {
  runWorkspaceScript("build", names, { stdio: ["ignore", "pipe", "pipe"] });
  const packages = new Map();
  for (const entry of await readdir(join(WORKSPACE_ROOT, "packages"), { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const directory = join(WORKSPACE_ROOT, "packages", entry.name);
    const manifest = JSON.parse(await readFile(join(directory, "package.json"), "utf8"));
    packages.set(manifest.name, { directory, version: manifest.version });
  }
  const tarballs = new Map();
  for (const name of names) {
    const workspace = packages.get(name);
    if (!workspace) throw new Error(`Unknown workspace package: ${name}`);
    const filename = join(
      destination,
      `${name.replace(/^@/u, "").replaceAll("/", "-")}-${workspace.version}.tgz`,
    );
    run("bun", ["pm", "pack", "--filename", filename, "--quiet"], {
      cwd: workspace.directory,
    });
    const packed = await stat(filename);
    if (!packed.isFile() || packed.size === 0) {
      throw new Error(`bun pm pack did not produce a tarball for ${name}`);
    }
    tarballs.set(name, filename);
  }
  return tarballs;
}

/**
 * Creates one clean consumer: tarball dependencies, npm overrides pinning every
 * internal edge to its tarball, the caller's extra registry dependencies, and
 * `nodenext` strict typechecking for the consumer's own sources.
 */
export async function createConsumer({
  label,
  packages,
  dependencies = {},
  files,
  types = [],
  skipLibCheck = false,
}) {
  const directory = await mkdtemp(join(tmpdir(), `oaath-${label}-`));
  const tarballs = await packWorkspacePackages(packages, directory);
  const pinned = Object.fromEntries([...tarballs].map(([name, path]) => [name, `file:${path}`]));
  await writeFile(
    join(directory, "package.json"),
    `${JSON.stringify(
      {
        name: `oaath-${label}-consumer`,
        version: "0.0.0",
        private: true,
        type: "module",
        dependencies: { ...pinned, ...dependencies },
        // `workspace:*` packed as an unpublished version; pin it to the tarball.
        overrides: pinned,
      },
      null,
      2,
    )}\n`,
  );
  await writeFile(
    join(directory, "tsconfig.json"),
    `${JSON.stringify(
      {
        compilerOptions: {
          target: "ES2022",
          module: "nodenext",
          moduleResolution: "nodenext",
          strict: true,
          noUncheckedIndexedAccess: true,
          exactOptionalPropertyTypes: true,
          verbatimModuleSyntax: true,
          noEmit: true,
          // Off by default, so a published declaration must stand on its own
          // with no ambient global assumed. A consumer that legitimately needs
          // `@types/node` turns it on, because that package's own declarations
          // are internally inconsistent and are not this repo's surface; the
          // consumer's use of the published types is still fully checked.
          skipLibCheck,
          types,
        },
        include: ["*.ts"],
      },
      null,
      2,
    )}\n`,
  );
  for (const [name, contents] of Object.entries(files)) {
    await writeFile(join(directory, name), contents);
  }
  run("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error"], { cwd: directory });
  return {
    directory,
    /** Runs one consumer module under Node and returns its stdout. */
    node: (file) => run(process.execPath, [file], { cwd: directory }),
    /** Typechecks the consumer's sources with the workspace TypeScript. */
    typecheck: () =>
      run(join(WORKSPACE_ROOT, "node_modules/.bin/tsc"), ["--project", directory], {
        cwd: directory,
      }),
    cleanup: () => rm(directory, { recursive: true, force: true }),
  };
}

/** Fails closed with the smallest possible diagnostic. */
export function assert(condition, message) {
  if (!condition) throw new Error(message);
}

/**
 * The export names the workspace build produced for one package, read from the
 * bundle's trailing `export { ... };` statement. The packed consumer must
 * observe exactly these, which is what proves `files` and `exports`
 * deliver the built surface. The surface list itself is owned by
 * each package's own boundary test and is never restated here.
 *
 * Read rather than imported so only the clean consumer loads the bundles and
 * their dependencies; workspace source conditions cannot affect the proof.
 */
export async function builtExports(name, entry = "index.js") {
  const bundle = await readFile(
    new URL(`../packages/${name}/dist/${entry}`, import.meta.url),
    "utf8",
  );
  const statements = [...bundle.matchAll(/export\s*\{([^}]*)\}\s*;/gu)];
  const last = statements[statements.length - 1];
  if (last?.[1] === undefined) {
    throw new Error(`${name}/dist/${entry} has no export statement`);
  }
  return last[1]
    .split(",")
    .map((entry) =>
      entry
        .trim()
        .split(/\s+as\s+/u)
        .pop(),
    )
    .filter((name) => name !== undefined && name !== "")
    .sort();
}
