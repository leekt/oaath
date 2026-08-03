import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scrubLiveProviderEnvironment } from "./live-provider-environment.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const packageManifest = JSON.parse(await readFile(join(repository, "package.json"), "utf8"));
const testFiles = [
  "package.test.ts",
  "kernel-runtime-capabilities.test.ts",
  "identity-profile.test.ts",
  "grant-policy.test.ts",
  "permission-protocol.test.ts",
  "grant.test.ts",
  "grant-transition.test.ts",
  "prepared-user-operation.test.ts",
  "store.test.ts",
  "operation-observer.test.ts",
  "stack-a-public-acceptance.test.ts",
  "local-kernel-handle-ops.test.ts",
  "local-kernel-handle-ops.anvil.test.ts",
];
const publicImportReplacements = new Map([
  ['from "../src/index.js"', 'from "@leekt/ogp"'],
  ['from "../src/testing.js"', 'from "@leekt/ogp/testing"'],
]);

function fail(message) {
  throw new Error(`Stack A acceptance failed: ${message}`);
}

async function installedVersion(name) {
  const manifest = JSON.parse(
    await readFile(join(repository, "node_modules", ...name.split("/"), "package.json"), "utf8"),
  );
  if (typeof manifest.version !== "string") fail(`${name} version is unavailable`);
  return manifest.version;
}

async function copyPublicTest(file, consumer) {
  let source = await readFile(join(repository, "test", file), "utf8");
  for (const [workspaceImport, packageImport] of publicImportReplacements) {
    source = source.replaceAll(workspaceImport, packageImport);
  }
  if (
    source.includes("../src/") ||
    source.includes("leekt/deployer") ||
    !source.includes('from "@leekt/ogp"')
  ) {
    fail(`${file} does not consume only accepted package exports`);
  }
  const destination = join(consumer, "test", file);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, source, { encoding: "utf8", flag: "wx" });
}

function run(command, arguments_, cwd, environment) {
  const result = spawnSync(command, arguments_, { cwd, env: environment, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exitCode = result.status ?? 1;
  return result.status === 0;
}

if (process.env.OGP_REQUIRE_ANVIL !== "1") fail("OGP_REQUIRE_ANVIL=1 is required");
const tarball = join(repository, ".artifacts", "leekt-ogp-0.0.0.tgz");
const consumer = await mkdtemp(join(tmpdir(), "ogp-stack-a-acceptance-"));
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";

try {
  const dependencies = {
    "@account-abstraction/contracts": await installedVersion("@account-abstraction/contracts"),
    "@leekt/ogp": `file:${tarball}`,
    "@types/node": await installedVersion("@types/node"),
    "@zerodev/sdk": await installedVersion("@zerodev/sdk"),
    "fast-check": await installedVersion("fast-check"),
    typescript: await installedVersion("typescript"),
    viem: await installedVersion("viem"),
    vitest: await installedVersion("vitest"),
  };
  await writeFile(
    join(consumer, "package.json"),
    `${JSON.stringify(
      {
        name: "ogp-stack-a-packed-acceptance",
        private: true,
        type: "module",
        packageManager: packageManifest.packageManager,
        dependencies,
      },
      null,
      2,
    )}\n`,
    { encoding: "utf8", flag: "wx" },
  );
  await writeFile(
    join(consumer, "tsconfig.json"),
    `${JSON.stringify(
      {
        compilerOptions: {
          target: "ES2022",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          strict: true,
          noUncheckedIndexedAccess: true,
          exactOptionalPropertyTypes: true,
          verbatimModuleSyntax: true,
          noEmit: true,
          skipLibCheck: true,
          types: ["node", "vitest/globals"],
        },
        include: ["test"],
      },
      null,
      2,
    )}\n`,
    { encoding: "utf8", flag: "wx" },
  );
  await Promise.all(testFiles.map((file) => copyPublicTest(file, consumer)));
  const fixtureDirectory = join(consumer, "test", "fixtures");
  await mkdir(fixtureDirectory, { recursive: true });
  await copyFile(
    join(repository, "test", "fixtures", "kernel-v3.3-bytecode.json"),
    join(fixtureDirectory, "kernel-v3.3-bytecode.json"),
  );

  const environment = {
    ...scrubLiveProviderEnvironment(process.env),
    OGP_REQUIRE_ANVIL: "1",
  };
  if (!run(pnpm, ["install", "--offline", "--ignore-scripts"], consumer, environment)) {
    fail("packed consumer installation failed");
  }
  if (!run(pnpm, ["exec", "tsc", "--noEmit"], consumer, environment)) {
    fail("packed consumer typecheck failed");
  }
  if (
    !run(
      pnpm,
      ["exec", "vitest", "run", ...testFiles.map((file) => `test/${file}`)],
      consumer,
      environment,
    )
  ) {
    fail("packed consumer evidence failed");
  }
} finally {
  await rm(consumer, { recursive: true, force: true });
}
