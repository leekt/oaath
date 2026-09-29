import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { getCreate2Address, keccak256 } from "viem";

const fixtures = new URL("../test/fixtures/", import.meta.url);
const input = JSON.parse(
  await readFile(new URL("kernel-rate-limit-solc-input.json", fixtures), "utf8"),
);
const expected = JSON.parse(
  await readFile(new URL("kernel-rate-limit-deployment.json", fixtures), "utf8"),
);
assert.equal(expected.version, "oaath.kernel-rate-limit-artifact/v1");
const directory = await mkdtemp(join(tmpdir(), "oaath-rate-limit-artifact-"));
try {
  for (const [path, source] of Object.entries(input.sources)) {
    await mkdir(dirname(join(directory, path)), { recursive: true });
    await writeFile(join(directory, path), source.content);
  }
  const settings = input.settings;
  await writeFile(
    join(directory, "foundry.toml"),
    [
      "[profile.default]",
      'src = "src"',
      'solc_version = "0.8.30"',
      `evm_version = ${JSON.stringify(settings.evmVersion)}`,
      `via_ir = ${settings.viaIR}`,
      `optimizer = ${settings.optimizer.enabled}`,
      `optimizer_runs = ${settings.optimizer.runs}`,
      "cbor_metadata = false",
      'bytecode_hash = "none"',
      `remappings = ${JSON.stringify(settings.remappings)}`,
      "",
    ].join("\n"),
  );
  const env = { FOUNDRY_EVM_VERSION: settings.evmVersion };
  for (const key of ["PATH", "HOME", "TMPDIR"]) if (process.env[key]) env[key] = process.env[key];
  const result = spawnSync("forge", ["build", expected.source, "--root", directory], {
    env,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, "rate_limit_artifact_compile_failed");
  const compiled = JSON.parse(
    await readFile(join(directory, "out/RateLimitPolicy.sol/RateLimitPolicy.json"), "utf8"),
  );
  const metadata = JSON.parse(compiled.rawMetadata);
  assert.equal(metadata.compiler.version, expected.compiler.version);
  assert.equal(metadata.settings.evmVersion, settings.evmVersion);
  assert.deepEqual(metadata.settings.optimizer, settings.optimizer);
  assert.equal(
    expected.deploymentInput,
    `0x${"00".repeat(32)}${compiled.bytecode.object.slice(2)}`,
  );
  assert.equal(keccak256(compiled.deployedBytecode.object), expected.runtimeCodeHash);
  assert.equal(
    getCreate2Address({
      from: "0x4e59b44847b379578588920ca78fbf26c0b4956c",
      salt: `0x${"00".repeat(32)}`,
      bytecode: compiled.bytecode.object,
    }).toLowerCase(),
    expected.expectedAddress,
  );
  process.stdout.write(
    "Verified resetting rate-limit source, compiler, deployment input, address and runtime hash.\n",
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
