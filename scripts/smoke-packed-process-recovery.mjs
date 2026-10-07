import { scrubLiveProviderEnvironment } from "./live-provider-environment.mjs";
import { createConsumer } from "./packed-consumer.mjs";

// Producer must die after broadcast, before acknowledgement or SDK observation; only normal SDK store writes survive.
const files = {
  "producer.mjs": `
import assert from "node:assert/strict";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
import { createLocalAnvilFixture } from "@oaath/testing/anvil";
import { createSqliteOperationStore } from "@oaath/testing";
import { join } from "node:path";
let fixture;
try {
  const calls = [{ target: "0x4444444444444444444444444444444444444444", data: "0x12345678", value: "1" }];
  fixture = await createLocalAnvilFixture({ stateDirectory: process.argv[2], submission: (open) => async (request) => {
    const session = await open(request);
    return { ...session, async send() {
      await session.send();
      const store = createSqliteOperationStore(join(process.argv[2], "client.sqlite"));
      try {
        const record = await store.get({ grantId: request.prepared.grantId, chainId: request.prepared.chainId, kind: "execution" });
        assert.equal(record.value.state, "submission_attempted");
      } finally { await store.close(); }
      assert.equal(fixture.approvalCount, 1);
      assert.equal(fixture.submissionCount, 1);
      process.send({ type: "broadcast", grantId: request.prepared.grantId, operationId: request.prepared.userOperationHash, calls });
      // Hold the reply until the parent kills this process. The SDK never acknowledges it.
      await new Promise(() => {});
    } };
  } });
  process.send({ type: "environment", recovery: fixture.recovery, processIds: fixture.processIds });
  const oaath = await fixture.openClient();
  const connection = await oaath.connect();
  const grant = await connection.requestPermission({ chainScope: "all", expiresIn: 1800, perChainOperationLimit: 4, permissions: [{ calls: [{ target: calls[0].target, selectors: [calls[0].data], valueLimit: "1" }] }] });
  await grant.sendCalls({ chain: fixture.chainIds[0], calls });
  throw new Error("broadcast reply unexpectedly reached the SDK");
} catch {
  if (fixture) await fixture.close().catch(() => undefined);
  process.send({ type: "failed" });
  process.exit(1);
}
`,
  "recover.mjs": `
import assert from "node:assert/strict";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
import { openLocalAnvilRecoveryClient } from "@oaath/testing/anvil";
let oaath;
let stage = "open";
process.once("message", async ({ recovery, stateDirectory, reference, unreadable = false }) => {
  try {
    oaath = await openLocalAnvilRecoveryClient({ recovery, stateDirectory });
    stage = "resume";
    const connection = await oaath.connect();
    const grant = await connection.resume();
    stage = "lookup";
    const operation = await grant.getOperation({ chain: recovery.chains[0].chainId, id: reference.operationId });
    assert.equal(operation.id, reference.operationId);
    stage = unreadable ? "unreadable" : "execution";
    if (unreadable) {
      await assert.rejects(operation.execution(), { code: "oaath_client_observation_unavailable" });
      stage = "unreadable_status";
      assert.equal(operation.outcome.status, "pending");
      assert.equal(operation.outcome.reason, "provider_unavailable");
      stage = "unreadable_state";
      assert.equal(operation.outcome.state, "submission_attempted");
    } else {
      const evidence = await operation.execution();
      assert.equal(evidence.outcome, "success");
      assert.equal(evidence.grantId, reference.grantId);
      assert.deepEqual(evidence.calls, reference.calls);
    }
    // The recovery composition cannot turn observation failure or success into a new send.
    stage = "send_denied";
    await assert.rejects(grant.sendCalls({ chain: recovery.chains[0].chainId, calls: reference.calls }));
    stage = "permission_denied";
    await assert.rejects(connection.requestPermission({ chainScope: "all", expiresIn: 1800, perChainOperationLimit: 4, permissions: [{ calls: [{ target: reference.calls[0].target, selectors: [reference.calls[0].data], valueLimit: "1" }] }] }));
    stage = "close";
    await oaath.close(); oaath = undefined;
    process.send({ type: unreadable ? "unreadable" : "recovered", id: operation.id });
    process.disconnect();
  } catch {
    if (oaath) await oaath.close().catch(() => undefined);
    process.send({ type: "failed", stage });
    process.exit(1);
  }
});
`,
  "index.mjs": `
import assert from "node:assert/strict";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
import { fork } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
const stateDirectory = await mkdtemp(join(tmpdir(), "oaath-process-state-"));
let producer, recovered;
let processIds = [];
let rpcProxy;
function message(child, expected) {
  return new Promise((resolve, reject) => {
    const done = (error, value) => {
      clearTimeout(timer);
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => done(new Error("process_recovery_timeout")), 30000);
    const onMessage = (value) => {
      if (value.type === "failed") done(new Error("process_recovery_failed_" + (value.stage ?? "producer")));
      else if (value.type === expected) done(null, value);
    };
    const onError = () => done(new Error("process_recovery_spawn_failed"));
    const onExit = () => done(new Error("process_recovery_exited_early"));
    child.on("message", onMessage);
    child.once("error", onError);
    child.once("exit", onExit);
  });
}
async function stopped(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise(resolve => child.once("exit", resolve));
  child.kill("SIGKILL");
  await exited;
}
async function recover(recovery, reference, unreadable) {
  recovered = fork("recover.mjs", [], { stdio: ["ignore","ignore","ignore","ipc"] });
  assert.notEqual(recovered.pid, producer.pid);
  const result = message(recovered, unreadable ? "unreadable" : "recovered");
  const closed = new Promise(resolve => recovered.once("exit", resolve));
  recovered.send({ recovery, stateDirectory, reference, unreadable });
  assert.equal((await result).id, reference.operationId);
  await closed;
  assert.equal(recovered.exitCode, 0);
}
async function nonce(recovery) {
  const chain = recovery.chains[0];
  const response = await fetch(chain.rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({jsonrpc:"2.0", id:1, method:"eth_getTransactionCount", params:[chain.feePayer.address,"latest"]}), signal: AbortSignal.timeout(5000) });
  const value = await response.json();
  assert.match(value.result, /^0x[0-9a-f]+$/);
  return value.result;
}
try {
  producer = fork("producer.mjs", [stateDirectory], { stdio: ["ignore","ignore","ignore","ipc"] });
  const submitted = message(producer, "broadcast");
  void submitted.catch(() => undefined);
  const environment = await message(producer, "environment");
  processIds = environment.processIds;
  const reference = await submitted;
  const before = await nonce(environment.recovery);
  await stopped(producer);
  // An owned loopback proxy corrupts only receipt discovery. Other local reads remain real.
  rpcProxy = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const payload = Buffer.concat(chunks).toString("utf8");
      const body = JSON.parse(payload);
      response.setHeader("content-type", "application/json");
      if (body.method === "eth_getLogs") response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: null }));
      else {
        const upstream = await fetch(environment.recovery.chains[0].rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: payload, signal: AbortSignal.timeout(5000) });
        response.end(await upstream.text());
      }
    } catch { response.statusCode = 503; response.end(); }
  });
  await new Promise(resolve => rpcProxy.listen(0, "127.0.0.1", resolve));
  const unavailable = { ...environment.recovery, chains: environment.recovery.chains.map(chain => ({ ...chain, rpcUrl: "http://127.0.0.1:" + rpcProxy.address().port })) };
  await recover(unavailable, reference, true);
  assert.equal(await nonce(environment.recovery), before);
  await recover(environment.recovery, reference, false);
  assert.equal(await nonce(environment.recovery), before);
  process.stdout.write("SDK process recovery after lost broadcast reply: unreadable evidence stays unresolved; same operation, exact calls, zero resubmission\\n");
} finally {
  await Promise.all([stopped(producer), stopped(recovered)]);
  if (rpcProxy) await new Promise(resolve => rpcProxy.close(resolve));
  for (const pid of processIds) { try { process.kill(pid, "SIGTERM"); } catch {} }
  // Wait for owned chains to exit before removing their clients' durable state.
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const alive = processIds.filter(pid => { try { process.kill(pid, 0); return true; } catch { return false; } });
    if (alive.length === 0) break;
    if (attempt === 99) { for (const pid of alive) { try { process.kill(pid, "SIGKILL"); } catch {} } }
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  await rm(stateDirectory, { recursive: true, force: true });
}
`,
  "surface.ts": `import { createLocalAnvilFixture, openLocalAnvilRecoveryClient } from "@oaath/testing/anvil"; export { createLocalAnvilFixture, openLocalAnvilRecoveryClient };`,
};
const saved = process.env;
process.env = scrubLiveProviderEnvironment(process.env);
let consumer;
try {
  consumer = await createConsumer({
    label: "process-recovery",
    packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing"],
    dependencies: { "@types/node": "22.13.0" },
    types: ["node"],
    skipLibCheck: true,
    files,
  });
  consumer.typecheck();
  process.stdout.write(consumer.node("index.mjs"));
} finally {
  await consumer?.cleanup();
  process.env = saved;
}
