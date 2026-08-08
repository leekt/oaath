import { execFileSync, spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { concatHex, getCreate2Address, keccak256, stringToHex } from "viem";

const PACKAGE_ROOT = fileURLToPath(new URL("../", import.meta.url));
const SOURCE_PATH = new URL("../src/OaathKernelV4ValidityPolicy.sol", import.meta.url);
const FOUNDRY_CONFIG_PATH = new URL("../foundry.toml", import.meta.url);
const FORGE_ARTIFACT_PATH = new URL(
  "../out/OaathKernelV4ValidityPolicy.sol/OaathKernelV4ValidityPolicy.json",
  import.meta.url,
);
const PINNED_ARTIFACT_PATH = new URL(
  "../artifacts/OaathKernelV4ValidityPolicy.json",
  import.meta.url,
);
const CREATE2_DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c";
const CREATE2_DEPLOYER_RUNTIME =
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";
const ZERO_SALT = `0x${"00".repeat(32)}`;
const LOCAL_SENDER = "0x000000000000000000000000000000000000a11c";
const EXPECTED_FOUNDRY_VERSION = "1.7.1";
const EXPECTED_SOLC_VERSION = "0.8.24+commit.e11b9ed9";
const LOCAL_DEPLOYMENT_TIMEOUT_MS = 10_000;

function fail(message) {
  throw new Error(message);
}

function exactHex(value, label) {
  if (typeof value !== "string" || !/^0x(?:[0-9a-f]{2})+$/u.test(value)) {
    return fail(`${label} is not canonical bytecode`);
  }
  return value;
}

function foundryVersion() {
  const output = execFileSync("forge", ["--version"], { encoding: "utf8", cwd: PACKAGE_ROOT });
  const version = /forge Version: (\d+\.\d+\.\d+)/u.exec(output)?.[1];
  if (version !== EXPECTED_FOUNDRY_VERSION) {
    return fail(
      `Foundry ${EXPECTED_FOUNDRY_VERSION} is required; received ${version ?? "unknown"}`,
    );
  }
  return version;
}

function anvilVersion() {
  const output = execFileSync("anvil", ["--version"], { encoding: "utf8", cwd: PACKAGE_ROOT });
  const version = /anvil Version: (\d+\.\d+\.\d+)/u.exec(output)?.[1];
  if (version !== EXPECTED_FOUNDRY_VERSION) {
    return fail(`Anvil ${EXPECTED_FOUNDRY_VERSION} is required; received ${version ?? "unknown"}`);
  }
  return version;
}

async function rpc(url, method, params = []) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const payload = await response.json();
  if (!response.ok || payload.error) {
    return fail(`local Anvil ${method} failed`);
  }
  return payload.result;
}

function localAnvil() {
  const process = spawn(
    "anvil",
    ["--port", "0", "--accounts", "0", "--hardfork", "paris", "--color", "never"],
    { cwd: PACKAGE_ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  const listening = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`local Anvil did not start within ${LOCAL_DEPLOYMENT_TIMEOUT_MS}ms`));
    }, LOCAL_DEPLOYMENT_TIMEOUT_MS);
    const inspect = (chunk) => {
      output += chunk.toString();
      const port = /Listening on 127\.0\.0\.1:(\d+)/u.exec(output)?.[1];
      if (port) {
        clearTimeout(timeout);
        resolve(`http://127.0.0.1:${port}`);
      }
    };
    process.stdout.on("data", inspect);
    process.stderr.on("data", inspect);
    process.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    process.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`local Anvil exited before listening (${code})`));
    });
  });
  return { process, listening };
}

async function waitForReceipt(url, transactionHash) {
  const deadline = Date.now() + LOCAL_DEPLOYMENT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const receipt = await rpc(url, "eth_getTransactionReceipt", [transactionHash]);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return fail(`local deployment receipt timed out: ${transactionHash}`);
}

async function verifyLocalDeployment(deploymentInput, expectedAddress, runtimeCodeHash) {
  anvilVersion();
  const anvil = localAnvil();
  try {
    const url = await anvil.listening;
    await rpc(url, "anvil_setCode", [CREATE2_DEPLOYER, CREATE2_DEPLOYER_RUNTIME]);
    const deployerCode = await rpc(url, "eth_getCode", [CREATE2_DEPLOYER, "latest"]);
    if (deployerCode.toLowerCase() !== CREATE2_DEPLOYER_RUNTIME) {
      return fail("local Anvil did not install the canonical singleton deployer runtime");
    }
    await rpc(url, "anvil_setBalance", [LOCAL_SENDER, "0x21e19e0c9bab2400000"]);
    await rpc(url, "anvil_impersonateAccount", [LOCAL_SENDER]);
    const transactionHash = await rpc(url, "eth_sendTransaction", [
      { from: LOCAL_SENDER, to: CREATE2_DEPLOYER, data: deploymentInput, gas: "0x7a1200" },
    ]);
    const receipt = await waitForReceipt(url, transactionHash);
    if (receipt.status !== "0x1") {
      return fail("local singleton deployment reverted");
    }
    const deployedCode = await rpc(url, "eth_getCode", [expectedAddress, "latest"]);
    if (deployedCode === "0x" || keccak256(deployedCode) !== runtimeCodeHash) {
      return fail("local singleton deployment runtime hash did not match the Forge artifact");
    }
  } finally {
    anvil.process.kill("SIGTERM");
  }
}

async function expectedArtifact() {
  const [source, foundryConfig, rawForgeArtifact] = await Promise.all([
    readFile(SOURCE_PATH, "utf8"),
    readFile(FOUNDRY_CONFIG_PATH, "utf8"),
    readFile(FORGE_ARTIFACT_PATH, "utf8"),
  ]);
  const forgeArtifact = JSON.parse(rawForgeArtifact);
  const metadata =
    typeof forgeArtifact.metadata === "string"
      ? JSON.parse(forgeArtifact.metadata)
      : forgeArtifact.metadata;
  const compiler = {
    foundry: foundryVersion(),
    solc: metadata?.compiler?.version,
    viaIR: metadata?.settings?.viaIR,
    optimizer: metadata?.settings?.optimizer?.enabled,
    optimizerRuns: metadata?.settings?.optimizer?.runs,
    evmVersion: metadata?.settings?.evmVersion,
    bytecodeHash: metadata?.settings?.metadata?.bytecodeHash,
    cborMetadata: metadata?.settings?.metadata?.appendCBOR,
  };
  const expectedCompiler = {
    foundry: EXPECTED_FOUNDRY_VERSION,
    solc: EXPECTED_SOLC_VERSION,
    viaIR: true,
    optimizer: true,
    optimizerRuns: 200,
    evmVersion: "paris",
    bytecodeHash: "none",
    cborMetadata: false,
  };
  if (JSON.stringify(compiler) !== JSON.stringify(expectedCompiler)) {
    return fail(`Forge artifact compiler settings drifted: ${JSON.stringify(compiler)}`);
  }

  const creationCode = exactHex(
    forgeArtifact?.bytecode?.object,
    "OaathKernelV4ValidityPolicy creation code",
  );
  const runtimeCode = exactHex(
    forgeArtifact?.deployedBytecode?.object,
    "OaathKernelV4ValidityPolicy runtime code",
  );
  const creationCodeHash = keccak256(creationCode);
  const runtimeCodeHash = keccak256(runtimeCode);
  const deploymentInput = concatHex([ZERO_SALT, creationCode]);
  const expectedAddress = getCreate2Address({
    from: CREATE2_DEPLOYER,
    salt: ZERO_SALT,
    bytecodeHash: creationCodeHash,
  }).toLowerCase();
  await verifyLocalDeployment(deploymentInput, expectedAddress, runtimeCodeHash);

  return {
    version: "oaath.kernel-v4-validity-policy-artifact/v1",
    contract: "OaathKernelV4ValidityPolicy",
    source: "src/OaathKernelV4ValidityPolicy.sol",
    sourceKeccak256: keccak256(stringToHex(source)),
    foundryConfigKeccak256: keccak256(stringToHex(foundryConfig)),
    compiler,
    deployment: {
      deployer: CREATE2_DEPLOYER,
      deployerRuntimeCodeHash: keccak256(CREATE2_DEPLOYER_RUNTIME),
      salt: ZERO_SALT,
      creationCodeHash,
      runtimeCodeHash,
      expectedAddress,
      deploymentInput,
    },
  };
}

const mode = process.argv[2];
if (mode !== "--write" && mode !== "--check") {
  fail("usage: node scripts/artifact.mjs --write|--check");
}
const serialized = `${JSON.stringify(await expectedArtifact(), null, 2)}\n`;
if (mode === "--write") {
  await mkdir(new URL("../artifacts/", import.meta.url), { recursive: true });
  await writeFile(PINNED_ARTIFACT_PATH, serialized, "utf8");
  process.stdout.write("generated deterministic Kernel validity policy artifact\n");
} else {
  let current;
  try {
    current = await readFile(PINNED_ARTIFACT_PATH, "utf8");
  } catch {
    fail("pinned artifact is missing; run pnpm artifact:generate");
  }
  if (current !== serialized) {
    fail("pinned artifact drifted; run pnpm artifact:generate and review the bytecode change");
  }
  process.stdout.write("verified deterministic Kernel validity policy artifact\n");
}
