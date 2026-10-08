/** Count real HTTP requests through the packed SDK; no external RPC access. */
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "rpc-coalescing",
  packages: ["@oaath/protocol", "@oaath/sdk"],
  files: {
    "run.mjs": `
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { createCetaneChainPorts } from "@oaath/sdk/cetane";

const requests = [];
let code = "0x6000";
let unavailable = false;
const server = createServer(async (request, response) => {
  let body = "";
  for await (const chunk of request) body += chunk;
  const { id, method } = JSON.parse(body);
  requests.push(method);
  if (unavailable && method === "eth_getCode") {
    response.writeHead(503).end();
    return;
  }
  const result = method === "eth_chainId" ? "0x8f" : code;
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
try {
  const [chain] = createCetaneChainPorts({
    143: { publicRpcUrls: ["http://127.0.0.1:" + server.address().port] },
  }, { maxRequests: 10, maxConcurrency: 1, retry: { attempts: 3, delayMs: 0 } });
  const read = () => chain.reads.read({
    type: "code", chainId: 143, address: "0x" + "11".repeat(20),
  });
  assert.deepEqual(await Promise.all(Array.from({ length: 20 }, read)), Array(20).fill(code));
  assert.deepEqual(requests, ["eth_chainId", "eth_getCode"]);
  console.log("packed SDK: 20 concurrent reads = 2 HTTP requests (chain check + code)");

  code = "0x";
  assert.equal(await read(), "0x");
  assert.equal(requests.length, 3);

  unavailable = true;
  const failed = await Promise.allSettled(Array.from({ length: 20 }, read));
  for (const result of failed) {
    assert.equal(result.status, "rejected");
    assert.equal(result.reason.code, "oaath_rpc_unavailable");
  }
  assert.equal(requests.length, 8); // Three attempts and two chain rechecks.
  unavailable = false;
  code = "0x6001";
  assert.equal(await read(), code);
  assert.equal(requests.length, 9);
  assert.equal(await read(), code);
  assert.equal(requests.length, 10);
  await assert.rejects(read(), { code: "oaath_rpc_budget_exhausted" });
  assert.equal(requests.length, 10);
  console.log("packed SDK: fresh sequential reads, shared retries, failure eviction and hard budget verified");
} finally {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
`,
  },
});
try {
  console.log(consumer.node("run.mjs").trim());
} finally {
  await consumer.cleanup();
}
