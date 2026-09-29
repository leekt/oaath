/** Packed local wallet consumer in Chromium, with real IndexedDB and full page reload. */
import { createConsumer } from "./packed-consumer.mjs";

const AUTO = process.argv.includes("--auto");

const APP = `
import { createOAAth } from "@oaath/sdk";
import { createWalletClient, custom } from "viem";
import { KERNEL_V4_ENTRY_POINT_V07_CODE_HASH, OAATH_KERNEL_V4_VALIDITY_POLICY, OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH } from "@oaath/sdk/advanced";
import { kernelDeployment } from "@oaath/sdk/kernel";
const address = "0x1111111111111111111111111111111111111111";
const target = "0x2222222222222222222222222222222222222222";
const deployment = kernelDeployment({ chainId: 143, kernelVersion: "0.3.3" });
const now = () => Math.floor(Date.now() / 1000);
const wallet = createWalletClient({ account: window.ownerAddress, transport: custom({ request: (request) => window.walletRequest(request) }) });
const reads = { async read(request) {
  if (request.type === "runtime_code_hash") return request.address === OAATH_KERNEL_V4_VALIDITY_POLICY ? OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH : KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
  const result = { chain_id: 143, code: "0x6000", kernel_account_implementation: deployment.implementation, kernel_account_version: "kernel.advanced.v0.3.3", kernel_account_entrypoint: deployment.entryPoint.address, kernel_account_root_validator: "0x01" + deployment.ecdsaValidator.slice(2), kernel_ecdsa_owner: window.ownerAddress.toLowerCase(), kernel_v33_permission_nonce: "1" }[request.type];
  if (result === undefined) throw new Error("unexpected fixture read");
  return result;
} };
const chains = [{
  chainId: 143, reads, observation: { read: async () => null, close: async () => {} },
  routes: [{ kind: "erc4337-bundler", bundler: { probe: async () => ({ accepting: true, chainId: 143, supportedEntryPoints: [deployment.entryPoint.address] }) } }],
  submission: { open: async ({ prepared }) => ({ send: async () => { await window.sendOperation(prepared); throw new Error("lost reply"); }, close: async () => {} }) },
  quote: async () => ({ nonceKey: "0", sequence: "0", gas: { callGasLimit: "100000", verificationGasLimit: "2000000", preVerificationGas: "50000", maxFeePerGas: "1000000000", maxPriorityFeePerGas: "100000000" } }),
  usage: async ({ grantId, chainId }) => ({ version: "oaath.grant-policy-usage/v1", status: "complete", grantId, chainId, finalizedOperationCount: "0", through: { blockNumber: "1", blockHash: "0x" + "11".repeat(32), observedAt: now() } }),
  paymasterService: null, staticPaymasterConfigurationHash: null,
}];
const realm = createOAAth({ mode: "local", owner: wallet, account: address, chains });
const calls = { chain: 143, calls: [{ target, data: "0x12345678", value: "0" }], ...(window.signerAuto ? { signer: "auto" } : {}) };
window.app = {
  async start() {
    const grant = await (await realm.connect()).requestPermission({ chainScope: "all", permissions: [{ calls: [{ target, selectors: ["0x12345678"], valueLimit: "0" }] }], expiresIn: 1800, perChainOperationLimit: 2 });
    const review = await grant.reviewCalls(calls);
    if (review.signer !== (window.signerAuto ? "owner" : "session")) throw new Error("wrong reviewed signer");
    const operation = await grant.sendCalls(calls);
    localStorage.setItem("operation-id", operation.id);
    localStorage.setItem("binding-id", realm.binding.bindingId);
    return { state: grant.state, address: await grant.account(143), id: operation.id };
  },
  async resume() {
    const grant = await (await realm.connect()).resume();
    if (!grant || realm.binding.bindingId !== localStorage.getItem("binding-id")) throw new Error("Grant continuity lost");
    const id = localStorage.getItem("operation-id");
    const operation = await grant.getOperation({ chain: 143, id });
    if (!operation || operation.id !== id) throw new Error("saved operation missing");
    await operation.observe();
    let blocked = false;
    try { await grant.sendCalls(calls); } catch (error) { blocked = error.code === "oaath_client_state_conflict"; }
    if (!blocked) throw new Error("unresolved lane admitted another operation");
    return { state: grant.state, address: await grant.account(143), id };
  },
  close: () => realm.close(),
};
`;

const RUN = `
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { build } from "esbuild";
import puppeteer from "puppeteer-core";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
const owner = privateKeyToAccount(generatePrivateKey());
const auto = ${AUTO};
let approvals = 0, sends = 0, ownerSignatures = 0;
await build({ entryPoints: ["app.js"], bundle: true, format: "esm", platform: "browser", outfile: "bundle.js" });
const bundle = await readFile("bundle.js");
const server = createServer((request, response) => {
  if (request.url === "/bundle.js") response.writeHead(200, { "content-type": "application/javascript" }).end(bundle);
  else if (request.url === "/") response.writeHead(200, { "content-type": "text/html" }).end('<script>window.ownerAddress="' + owner.address + '";window.signerAuto=' + auto + '</script><script type="module" src="/bundle.js"></script>');
  else response.writeHead(404).end();
});
let browser;
try {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH ?? (process.platform === "darwin" ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "/usr/bin/google-chrome");
  browser = await puppeteer.launch({ executablePath, headless: true, userDataDir: join(process.cwd(), "browser-profile"), args: ["--no-sandbox"] });
  const page = await browser.newPage();
  await page.exposeFunction("walletRequest", async ({ method, params }) => {
    if (auto && method === "personal_sign" && params[1].toLowerCase() === owner.address.toLowerCase()) {
      ownerSignatures++;
      return owner.signMessage({ message: { raw: params[0] } });
    }
    if (method !== "eth_signTypedData_v4" || params[0].toLowerCase() !== owner.address.toLowerCase()) throw new Error("unexpected wallet request");
    approvals++;
    return owner.signTypedData(JSON.parse(params[1]));
  });
  await page.exposeFunction("sendOperation", async (prepared) => {
    if (prepared.userOperation.sender !== "0x1111111111111111111111111111111111111111" || BigInt(prepared.userOperation.nonce) >> 248n !== (auto ? 0n : 1n)) throw new Error("incorrect enable operation");
    sends++;
  });
  await page.goto("http://127.0.0.1:" + server.address().port);
  await page.waitForFunction(() => !!window.app);
  const before = await page.evaluate(() => window.app.start().catch((error) => { throw new Error(error.code + "/" + error.source); }));
  if (approvals !== 1 || sends !== 1 || ownerSignatures !== (auto ? 1 : 0) || before.state !== "active") throw new Error("local approval/send count mismatch");
  await page.evaluate(() => window.app.close());
  await page.reload();
  await page.waitForFunction(() => !!window.app);
  const after = await page.evaluate(() => window.app.resume().catch((error) => { throw new Error(error.code + "/" + error.source); }));
  if (JSON.stringify(before) !== JSON.stringify(after) || approvals !== 1 || sends !== 1 || ownerSignatures !== (auto ? 1 : 0)) throw new Error("reload changed authority or resubmitted");
  await page.evaluate(() => window.app.close());
  console.log(auto ? "packed Chromium auto Grant: one owner operation signature, no enable, page-reload recovery without resubmission" : "packed Chromium local Grant: one typed-data approval, one enable send, IndexedDB page-reload recovery without resubmission");
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
`;

const consumer = await createConsumer({
  label: "local-wallet-browser",
  packages: ["@oaath/protocol", "@oaath/sdk"],
  dependencies: { esbuild: "0.28.1", "puppeteer-core": "25.5.0", viem: "2.55.8" },
  files: {
    "app.js": APP,
    "run.mjs": RUN,
    "surface.ts": `
import { createOAAth, type OaathLocalConfiguration, type OaathLocalApprovalReview, type OaathGrantHandle, type OaathSendCallsInput } from "@oaath/sdk";
import { createViemChainPorts } from "@oaath/sdk/viem";
import { createWalletClient, custom, type EIP1193Provider, type Address } from "viem";
export async function send(grant: Readonly<OaathGrantHandle>, request: OaathSendCallsInput) {
  const review = await grant.reviewCalls({ ...request, signer: "auto" });
  if (review.signer === "owner") { const limits: null = review.perChainOperationLimit; void limits; }
  else { const limit: { count: number; intervalSeconds: number | null } = review.perChainOperationLimit; void limit; }
  return grant.sendCalls({ ...request, signer: "auto" });
}
export function connect(provider: EIP1193Provider, owner: Address, account: Address) {
  const wallet = createWalletClient({ account: owner, transport: custom(provider) });
  const config: OaathLocalConfiguration = { mode: "local", owner: wallet, account, chains: createViemChainPorts({ 143: { publicRpcUrls: ["http://localhost:8545"], bundlerUrl: "http://localhost:8546" } }), onApproval: async (review: Readonly<OaathLocalApprovalReview>) => { void review.policy; } };
  return createOAAth(config);
}
`,
  },
});
try {
  consumer.typecheck();
  process.stdout.write(consumer.node("run.mjs"));
} finally {
  await consumer.cleanup();
}
