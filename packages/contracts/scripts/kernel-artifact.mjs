import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { concatHex, encodeAbiParameters, getCreate2Address, keccak256 } from "viem";

// Reproduce the exact merged source; never fetch or deploy to a public chain.
const COMMIT = "c960b42d2ed4adb0d5328f6e762962debdf8e57a";
const REPOSITORY = "https://github.com/zerodevapp/kernel";
const [mode, source] = process.argv.slice(2);
assert(["--write", "--check"].includes(mode) && source, "Use --write|--check <Kernel checkout>");
const cwd = resolve(source);
const git = (...args) => execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
assert.equal(git("rev-parse", "HEAD"), COMMIT);
git(
  "diff",
  "--exit-code",
  COMMIT,
  "--",
  "src",
  "dependencies",
  "test/mock/ECDSAValidator.sol",
  "foundry.toml",
  "remappings.txt",
  "soldeer.lock",
);
execFileSync("forge", ["build", "--offline", "--force", "--skip", "test", "--skip", "script"], {
  cwd,
  stdio: "pipe",
  maxBuffer: 8 * 1024 * 1024,
});
const artifactUrl = new URL("../artifacts/KernelV4Runtime.json", import.meta.url);
const runtime = JSON.parse(await readFile(artifactUrl, "utf8"));
const deployer = "0x4e59b44847b379578588920ca78fbf26c0b4956c";
const entryPoint = "0x0000000071727de22e5e9d8baf0edac6f37da032";
const salt = `0x${"00".repeat(32)}`;
const sender = "0x00000000000000000000000000000000000a11ce";
const compiler = {
  version: "0.8.33+commit.64118f21",
  viaIR: true,
  optimizerRuns: 200,
  evmVersion: "prague",
  bytecodeHash: "none",
  cborMetadata: false,
};
async function artifact(name) {
  const result = JSON.parse(await readFile(resolve(cwd, `out/${name}.sol/${name}.json`), "utf8"));
  const { settings } = result.metadata;
  assert.equal(result.metadata.compiler.version, compiler.version);
  assert.equal(settings.viaIR, true);
  assert.deepEqual(settings.optimizer, { enabled: true, runs: 200 });
  assert.equal(settings.evmVersion, "prague");
  assert.deepEqual(settings.metadata, { bytecodeHash: "none", appendCBOR: false });
  return result;
}
async function component(name, args) {
  const built = await artifact(name);
  const bytecode = concatHex([
    built.bytecode.object,
    encodeAbiParameters(
      args.map(() => ({ type: "address" })),
      args,
    ),
  ]);
  return {
    source: `src/${name}.sol`,
    expectedAddress: getCreate2Address({ from: deployer, salt, bytecode }).toLowerCase(),
    deploymentInput: concatHex([salt, bytecode]),
  };
}
const kernelUups = await component("KernelUUPS", [entryPoint]);
const kernelImmutableEcdsa = await component("KernelImmutableECDSA", [entryPoint]);
const kernelFactory = await component("KernelFactory", [
  kernelUups.expectedAddress,
  kernelImmutableEcdsa.expectedAddress,
]);

async function verify(chainId) {
  const child = spawn(
    "anvil",
    [
      "--host",
      "127.0.0.1",
      "--port",
      "0",
      "--accounts",
      "0",
      "--chain-id",
      String(chainId),
      "--hardfork",
      "prague",
      "--color",
      "never",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  try {
    const url = await new Promise((resolveUrl, reject) => {
      const timer = setTimeout(() => reject(new Error("Local Anvil startup timed out")), 10000);
      let output = "";
      child.stdout.on("data", (chunk) => {
        output += chunk.toString();
        const port = /Listening on 127\.0\.0\.1:(\d+)/u.exec(output)?.[1];
        if (port) {
          clearTimeout(timer);
          resolveUrl(`http://127.0.0.1:${port}`);
        }
      });
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once("exit", () => {
        clearTimeout(timer);
        reject(new Error("Local Anvil exited"));
      });
    });
    let requests = 0;
    async function rpc(method, params) {
      assert(++requests <= 160, "Local artifact request budget exhausted");
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: requests, method, params }),
        signal: AbortSignal.timeout(5000),
      });
      const body = await response.json();
      assert(response.ok && !body.error, `Local artifact RPC failed: ${method}`);
      return body.result;
    }
    await rpc("anvil_setBalance", [sender, "0x3635c9adc5dea00000"]);
    await rpc("anvil_impersonateAccount", [sender]);
    const hashes = {};
    for (const [name, item] of Object.entries({
      kernelUups,
      kernelImmutableEcdsa,
      kernelFactory,
    })) {
      const hash = await rpc("eth_sendTransaction", [
        { from: sender, to: deployer, data: item.deploymentInput, gas: "0x989680" },
      ]);
      let receipt;
      for (let attempt = 0; attempt < 40; attempt++) {
        receipt = await rpc("eth_getTransactionReceipt", [hash]);
        if (receipt) break;
        await new Promise((done) => setTimeout(done, 25));
      }
      assert.equal(receipt?.status, "0x1", `${name} CREATE2 deployment failed`);
      const code = await rpc("eth_getCode", [item.expectedAddress, "latest"]);
      assert(code.length > 2 && (code.length - 2) / 2 <= 24576);
      hashes[name] = keccak256(code);
    }
    return hashes;
  } finally {
    child.kill("SIGTERM");
  }
}
const { kernelFactory: factoryHash } = await verify(421614);
runtime.version = "oaath.kernel-v4-runtime-artifacts/v2";
runtime.kernelSource = {
  repository: REPOSITORY,
  commit: COMMIT,
  sourceTree: git("rev-parse", "HEAD:src"),
  dependenciesTree: git("rev-parse", "HEAD:dependencies"),
  compiler,
  entryPointVersion: "0.7",
  note: "Compiled from Kernel PR #152. Factory runtime hash reproduced on local Anvil; no public deployment evidence is claimed.",
};
runtime.kernelUups = kernelUups;
runtime.kernelImmutableEcdsa = kernelImmutableEcdsa;
runtime.kernelFactory = { ...kernelFactory, runtimeCodeHash: factoryHash };
const validator = {
  repository: REPOSITORY,
  commit: COMMIT,
  source: "test/mock/ECDSAValidator.sol",
  bytecode: (await artifact("ECDSAValidator")).bytecode.object,
};
const profileSource = `// Generated by packages/contracts/scripts/kernel-artifact.mjs.\n// Kernel ${COMMIT}; hashes are local build evidence, not public deployment receipts.\nexport const KERNEL_V4_UUPS_IMPLEMENTATION_V07 = "${kernelUups.expectedAddress}" as const;\nexport const KERNEL_V4_FACTORY_V07 = "${kernelFactory.expectedAddress}" as const;\nexport const KERNEL_V4_FACTORY_V07_CODE_HASH = "${factoryHash}" as const;\n`;
const profile = execFileSync(
  process.execPath,
  [
    fileURLToPath(new URL("../../../node_modules/@biomejs/biome/bin/biome", import.meta.url)),
    "format",
    "--stdin-file-path=packages/sdk/src/kernel/deployment/v4-artifacts.ts",
  ],
  {
    cwd: fileURLToPath(new URL("../../../", import.meta.url)),
    input: profileSource,
    encoding: "utf8",
  },
);
for (const [url, content] of [
  [artifactUrl, `${JSON.stringify(runtime, null, 2)}\n`],
  [
    new URL("../../sdk/test/fixtures/kernel-ecdsa-mock.json", import.meta.url),
    `${JSON.stringify(validator, null, 2)}\n`,
  ],
  [new URL("../../sdk/src/kernel/deployment/v4-artifacts.ts", import.meta.url), profile],
]) {
  if (mode === "--write") await writeFile(url, content);
  else assert.equal(await readFile(url, "utf8"), content, `Stale Kernel artifact: ${url.pathname}`);
}
console.log(
  `Kernel ${COMMIT}: artifacts ${mode === "--write" ? "written" : "verified"}; local CREATE2 deployment, zero public RPC requests`,
);
