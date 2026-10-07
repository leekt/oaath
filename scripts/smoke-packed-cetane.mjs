/** The packed SDK resolves without viem and preserves its RPC budget and fresh reads. */
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "cetane-sdk",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/cli"],
  files: {
    "consumer.ts": `import { createCetaneChainPorts, type CetaneChainPortOptions } from "@oaath/sdk/cetane";
import type { OaathConnectedEoaPayer } from "@oaath/sdk";
import { createWalletClient, http } from "cetane";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { createExecution } from "cetane/execution/evm";
const signer = privateKeyToAccount(generatePrivateKey());
const wallet = createWalletClient({
  chain: { id: 143, name: "Fixture", nativeAA: false, execution: createExecution() },
  account: { address: signer.address }, signer, transport: http("http://127.0.0.1:1"),
});
const payer: OaathConnectedEoaPayer = { kind: "connected-eoa", wallet };
void payer;
const options: CetaneChainPortOptions = { maxRequests: 3 };
const ports = createCetaneChainPorts({ 143: { publicRpcUrls: ["http://127.0.0.1:1"] } }, options);
void ports;`,
    "consumer.mjs": `import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
const methods = [];
let code = "0x6000";
const server = createServer(async (request, response) => {
  let body = "";
  for await (const chunk of request) body += chunk;
  const { id, method } = JSON.parse(body);
  methods.push(method);
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ jsonrpc: "2.0", id, result: method === "eth_chainId" ? "0x8f" : code }));
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
try {
  const [chain] = createCetaneChainPorts({ 143: {
    publicRpcUrls: ["http://127.0.0.1:" + server.address().port],
  } }, { maxRequests: 3 });
  assert.equal(methods.length, 0);
  const read = () => chain.reads.read({ type: "code", chainId: 143, address: "0x" + "11".repeat(20) });
  assert.equal(await read(), "0x6000");
  code = "0x";
  assert.equal(await read(), "0x");
  assert.deepEqual(methods, ["eth_chainId", "eth_getCode", "eth_getCode"]);
  await assert.rejects(read(), { code: "oaath_rpc_budget_exhausted" });
  assert.equal(methods.length, 3);
  console.log("Packed Cetane SDK: no viem, lazy transport, fresh reads, and hard RPC budget verified.");
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
}`,
  },
});
try {
  consumer.typecheck();
  console.log(consumer.node("consumer.mjs").trim());
  if (!consumer.node("node_modules/@oaath/cli/dist/cli.mjs").includes("deploy-runtime"))
    throw new Error("Packed Cetane CLI did not load");
} finally {
  await consumer.cleanup();
}
