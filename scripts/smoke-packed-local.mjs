import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "local-anvil",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing"],
  dependencies: { "@types/node": "22.13.0", viem: "2.55.8" },
  types: ["node"],
  skipLibCheck: true,
  files: {
    "index.mjs": `
import assert from "node:assert/strict";
import { createLocalAnvilFixture } from "@oaath/testing/anvil";
import { createUserOperationObserver } from "@oaath/sdk/advanced";
import { createViemChainPorts } from "@oaath/sdk/viem";
import { kernelDeployment, NONCE_ALIGNMENT_PERMISSION_ID, verifyKernelPermissionNonceAlignmentCalls } from "@oaath/sdk/kernel";
import { createPublicClient, decodeEventLog, getCreate2Address, http } from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
await assert.rejects(createLocalAnvilFixture({ chainIds: [] }), /local_fixture_chains_invalid/);
await assert.rejects(createLocalAnvilFixture({ chainIds: [421614, 421614] }), /local_fixture_chains_invalid/);
const fixture = await createLocalAnvilFixture({ chainIds: [421614, 11155111] });
assert.match(NONCE_ALIGNMENT_PERMISSION_ID, /^0x[0-9a-f]{8}$/);
assert.equal(verifyKernelPermissionNonceAlignmentCalls({ account: "0x4444444444444444444444444444444444444444", calls: [], nonce: "1" }).status, "verified");
assert.equal(verifyKernelPermissionNonceAlignmentCalls({ account: "0x4444444444444444444444444444444444444444", calls: [{ target: "0x4444444444444444444444444444444444444444", data: "0x", value: "1" }], nonce: "1" }).status, "mismatch");
try {
  assert.match(fixture.rpcUrl(421614), /^http:\\/\\/127\\.0\\.0\\.1:\\d+$/);
  const client = await fixture.openClient();
  const connection = await client.connect();
  const factory = "0x4e59b44847b379578588920ca78fbf26c0b4956c";
  const salt = "0x" + "ab".repeat(32);
  const initCode = "0x6002600c60003960026000f36000";
  const deploymentCalls = [{ target: factory, data: salt + initCode.slice(2), value: "0" }];
  const grant = await connection.requestPermission({
    chainScope: "all", expiresIn: 1800, perChainOperationLimit: 4,
    permissions: [{ calls: [
      { target: "0x4444444444444444444444444444444444444444", selectors: ["0x12345678"], valueLimit: "1" },
      { target: factory, selectors: ["0xabababab"], valueLimit: "0" },
    ] }],
  });
  const calls = [{ target: "0x4444444444444444444444444444444444444444", data: "0x12345678", value: "1" }];
  const review = await grant.reviewCalls({ chain: 421614, calls: deploymentCalls });
  assert.equal(review.route, "erc4337-handleops");
  assert.equal(review.signer, "session");
  const first = await grant.sendCalls({ chain: 421614, calls: deploymentCalls });
  const deployed = await first.execution();
  assert.equal(deployed.outcome, "success");
  assert.deepEqual(deployed.calls, deploymentCalls);
  const reader = createPublicClient({ transport: http(fixture.rpcUrl(421614), { retryCount: 0 }) });
  assert.equal(await reader.getCode({ address: getCreate2Address({ from: factory, salt, bytecode: initCode }) }), "0x6000");
  const receipt = await reader.getTransactionReceipt({ hash: deployed.transactionHash });
  const event = receipt.logs.map(log => { try { return decodeEventLog({ abi: entryPoint07Abi, ...log }); } catch { return null; } }).find(log => log?.eventName === "UserOperationEvent" && log.args.userOpHash === first.id);
  assert.ok(event);
  const reference = { chainId: 421614, entryPoint: kernelDeployment({ chainId: 421614 }).entryPoint.address, account: event.args.sender.toLowerCase(), nonce: event.args.nonce.toString(), userOperationHash: first.id };
  const ports = () => createViemChainPorts({ 421614: { publicRpcUrls: [fixture.rpcUrl(421614)], bundlerUrl: fixture.rpcUrl(421614) } });
  const beforeFinality = ports()[0].observation;
  const observer = createUserOperationObserver({
    read: request => beforeFinality.read(request.type === "finalized_block" ? { type: "canonical_block", chainId: 421614, blockNumber: "0" } : request),
    close: beforeFinality.close,
  });
  const observationInput = { reference, transactionHash: deployed.transactionHash, observedAt: Date.now(), timeoutMs: 10000 };
  const included = await observer.observeReference(observationInput);
  assert.equal(included.status, "included");
  assert.equal(included.block.hash, receipt.blockHash);
  await observer.close();
  const recoveredObserver = createUserOperationObserver(ports()[0].observation);
  assert.equal((await recoveredObserver.observeReference(JSON.parse(JSON.stringify(observationInput)))).status, "finalized");
  await recoveredObserver.close();
  const last = await grant.sendCalls({ chain: 11155111, calls });
  assert.equal(last.outcome.status, "pending");
  const retained = { chain: last.chainId, id: last.id };
  assert.equal(fixture.submissionCount, 2);
  const reopened = await fixture.openClient();
  const restored = await (await reopened.connect()).resume();
  assert.ok(restored);
  const operation = await restored.getOperation(retained);
  assert.ok(operation);
  const execution = await operation.execution();
  assert.equal(execution.id, retained.id);
  assert.equal(execution.grantId, review.grantId);
  assert.equal(execution.chainId, 11155111);
  assert.equal(execution.outcome, "success");
  assert.deepEqual(execution.calls, calls);
  assert.equal(fixture.approvalCount, 1);
  assert.equal(fixture.submissionCount, 2);
  await fixture.closeClient();
} finally { await fixture.close(); }
await assert.rejects(fixture.openClient(), /local_fixture_closed/);
console.log("packed local fixture: raw CREATE2 deployment, two chains, one approval, exact recovery, zero resubmission");
`,
    "surface.ts": `
import type { Oaath } from "@oaath/sdk";
import { type KernelRuntime, kernelPermissionNonce, materializeKernelPermission } from "@oaath/sdk/kernel";
import type { ObserveUserOperationResult } from "@oaath/sdk/advanced";
export function inclusion(result: ObserveUserOperationResult) { return result.status === "included" ? result.block.hash : null; }
import { createLocalAnvilFixture, type LocalAnvilFixture } from "@oaath/testing/anvil";
export const create: () => Promise<Readonly<LocalAnvilFixture>> = createLocalAnvilFixture;
export function open(fixture: LocalAnvilFixture): Promise<Readonly<Oaath>> { return fixture.openClient(); }
export function permissionInputs(runtime: KernelRuntime<"0.3.3"> | KernelRuntime<"0.4.0">) {
  const nonce: Parameters<typeof kernelPermissionNonce>[0]["runtime"] = runtime;
  const materialization: Parameters<typeof materializeKernelPermission>[0]["runtime"] = runtime;
  return { nonce, materialization };
}
`,
  },
});
try {
  consumer.typecheck();
  process.stdout.write(consumer.node("index.mjs"));
} finally {
  await consumer.cleanup();
}
