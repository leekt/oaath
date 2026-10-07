import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { getCreate2Address } from "viem";

const mode = process.argv[2];
assert(["--write", "--check"].includes(mode), "Use --write|--check");
const input = JSON.parse(
  await readFile(new URL("../artifacts/KernelWeightedModules.input.json", import.meta.url), "utf8"),
);
const directory = await mkdtemp(join(tmpdir(), "oaath-weighted-artifact-"));
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
  const result = spawnSync(
    "forge",
    [
      "build",
      "src/validators/WeightedECDSAValidator.sol",
      "src/signers/WeightedECDSASigner.sol",
      "--offline",
      "--root",
      directory,
    ],
    { env, encoding: "utf8" },
  );
  assert.equal(result.status, 0, "weighted_artifact_compile_failed");
  const modules = {};
  for (const [name, source] of [
    ["WeightedECDSAValidatorV09", "src/validators/WeightedECDSAValidator.sol"],
    ["WeightedECDSASigner", "src/signers/WeightedECDSASigner.sol"],
  ]) {
    const sourceName = source.split("/").at(-1);
    const compiled = JSON.parse(
      await readFile(join(directory, `out/${sourceName}/${name}.json`), "utf8"),
    );
    const metadata = JSON.parse(compiled.rawMetadata);
    assert.equal(metadata.compiler.version, "0.8.30+commit.73712a01");
    assert.equal(metadata.settings.evmVersion, settings.evmVersion);
    assert.deepEqual(metadata.settings.optimizer, settings.optimizer);
    const salt = `0x${"00".repeat(32)}`;
    modules[name] = {
      source,
      expectedAddress: getCreate2Address({
        from: "0x4e59b44847b379578588920ca78fbf26c0b4956c",
        salt,
        bytecode: compiled.bytecode.object,
      }).toLowerCase(),
      deploymentInput: salt + compiled.bytecode.object.slice(2),
    };
  }
  const artifact = {
    version: "oaath.kernel-weighted-modules/v1",
    repository: "https://github.com/zerodevapp/kernel-7579-plugins",
    commit: "a267d7945f87fc54853b512c2c8d9316d6463e36",
    compiler: { version: "0.8.30+commit.73712a01", ...settings },
    note: "EIP-712 immutables bind runtime code to the chain and canonical CREATE2 address. No public deployment evidence is claimed.",
    ...modules,
  };
  const output = new URL("../artifacts/KernelWeightedModules.json", import.meta.url);
  const text = JSON.stringify(artifact, null, 2) + "\n";
  if (mode === "--write") await writeFile(output, text);
  else assert.equal(await readFile(output, "utf8"), text, "stale_weighted_modules_artifact");
  console.log(
    `Weighted module artifacts ${mode === "--write" ? "written" : "verified"}: ${modules.WeightedECDSAValidatorV09.expectedAddress}, ${modules.WeightedECDSASigner.expectedAddress}`,
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
