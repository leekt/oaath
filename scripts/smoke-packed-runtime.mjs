/** The published CLI bin against a real local deployment from packed artifacts. */

import runtime from "../packages/contracts/artifacts/KernelV4Runtime.json" with { type: "json" };
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "runtime-cli",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing", "@oaath/cli"],
  dependencies: { "@account-abstraction/contracts": "0.7.0", viem: "2.55.8" },
  files: {
    "run.mjs": `
import { execFile, spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { promisify } from "node:util";
import { createLocalAnvilFixture } from "@oaath/testing/anvil";
import { kernelDeployment } from "@oaath/sdk/kernel";
import { concat, createWalletClient, http, parseEther } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
const exec = promisify(execFile);
const bin = "./node_modules/.bin/oaath";
const help = await exec(bin, ["--help"]);
if (!help.stdout.includes("oaath doctor")) throw new Error("CLI help unavailable");
const fixture = await createLocalAnvilFixture({ chainIds: [421614] });
try {
  const { stdout } = await exec(bin, ["doctor", "--chain", "421614", "--rpc", fixture.rpcUrl(421614), "--json"]);
  const ready = JSON.parse(stdout);
  if (!ready.ready || ready.factoryBinding !== "verified" || ready.components.find(row => row.id === "kernelUups").status !== "verified") throw new Error("packed CLI did not verify the real runtime");
  let mismatch;
  try { await exec(bin, ["doctor", "--chain", "143", "--rpc", fixture.rpcUrl(421614), "--json"]); }
  catch (error) { if (error.code !== 1) throw error; mismatch = JSON.parse(error.stdout); }
  if (mismatch?.ready !== false || mismatch.error !== "chain_mismatch") throw new Error("packed CLI accepted the wrong chain");
  console.log("packed oaath bin: real deterministic runtime verified; wrong chain rejected; no deployment writes by doctor");
} finally { await fixture.close(); }

const child = spawn("anvil", ["--host", "127.0.0.1", "--port", "0", "--chain-id", "143", "--accounts", "0", "--hardfork", "prague", "--color", "never"], { stdio: ["ignore", "pipe", "pipe"] });
let timer, miningPromise, miningError;
try {
  const url = await new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error("local Anvil startup deadline")), 5000);
    const inspect = (chunk) => {
      output += chunk.toString();
      const port = /Listening on 127\\.0\\.0\\.1:(\\d+)/u.exec(output)?.[1];
      if (port) { clearTimeout(timeout); resolve("http://127.0.0.1:" + port); }
    };
    child.stdout.on("data", inspect); child.stderr.on("data", inspect);
    child.once("error", () => { clearTimeout(timeout); reject(new Error("local Anvil unavailable")); });
  });
  let requests = 0;
  const rpc = async (method, params = []) => {
    if (++requests > 300) throw new Error("local harness RPC budget exhausted");
    const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: requests, method, params }), signal: AbortSignal.timeout(5000) });
    const data = await response.json();
    if (!response.ok || data.error) throw new Error("local harness RPC failed");
    return data.result;
  };
  const key = generatePrivateKey();
  const account = privateKeyToAccount(key);
  await rpc("anvil_setBalance", [account.address, "0x" + parseEther("100").toString(16)]);
  const artifact = JSON.parse(await readFile(createRequire(import.meta.url).resolve("@account-abstraction/contracts/artifacts/EntryPoint.json"), "utf8"));
  const wallet = createWalletClient({ account, transport: http(url, { retryCount: 0 }) });
  const epHash = await wallet.sendTransaction({ chain: null, to: kernelDeployment({ chainId: 421614 }).create2Deployer, data: concat([${JSON.stringify(runtime.entryPoint.deploymentSalt)}, artifact.bytecode]), gas: 10000000n });
  // Anvil can answer sendTransaction before its automined block lands; poll the receipt, bounded.
  let epReceipt = null;
  for (let attempt = 0; attempt < 50 && epReceipt === null; attempt++) {
    if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 100));
    epReceipt = await rpc("eth_getTransactionReceipt", [epHash]);
  }
  if (epReceipt?.status !== "0x1") throw new Error("local EntryPoint prerequisite failed");
  const args = ["deploy-runtime", "--chain", "143", "--rpc", url, "--journal", "./deployment.sqlite", "--json"];
  const cleanEnv = { ...process.env }; delete cleanEnv.OAATH_DEPLOYER_PRIVATE_KEY;
  const plan = JSON.parse((await exec(bin, [...args, "--dry-run"], { env: cleanEnv })).stdout);
  if (plan.status !== "planned" || plan.missing.length !== 10) throw new Error("packed deployment plan incomplete");
  timer = setInterval(() => { if (miningPromise) return; miningPromise = rpc("anvil_mine", ["0x40"]).catch(() => { miningError = true; }).finally(() => { miningPromise = undefined; }); }, 200);
  const deployed = JSON.parse((await exec(bin, args, { env: { ...cleanEnv, OAATH_DEPLOYER_PRIVATE_KEY: key }, timeout: 60000 })).stdout);
  if (deployed.status !== "ready" || !deployed.readiness.ready || !deployed.readiness.passkeySessionsReady) throw new Error("packed deployment failed");
  const count = await rpc("eth_getTransactionCount", [account.address, "latest"]);
  const again = JSON.parse((await exec(bin, args, { env: cleanEnv })).stdout);
  if (again.status !== "ready" || count !== await rpc("eth_getTransactionCount", [account.address, "latest"])) throw new Error("packed rerun sent another transaction");
  if (miningError) throw new Error("local mining failed");
  console.log("packed deploy-runtime: ten missing contracts (including passkey-session modules) deployed and verified; repeat invocation needs no key and sends nothing");
} finally { clearInterval(timer); await miningPromise; child.kill("SIGTERM"); }
`,
  },
});

try {
  console.log(consumer.node("run.mjs"));
} finally {
  await consumer.cleanup();
}
