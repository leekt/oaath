import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "local-anvil",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing"],
  dependencies: { "@types/node": "22.13.0" },
  types: ["node"],
  skipLibCheck: true,
  files: {
    "index.mjs": `
import assert from "node:assert/strict";
import { createLocalAnvilFixture } from "@oaath/testing/anvil";
import { createUserOperationObserver } from "@oaath/sdk/advanced";
import { createCetaneChainPorts, classifyUserOperationError, readUserOperationFailure } from "@oaath/sdk/cetane";
import { kernelDeployment, NONCE_ALIGNMENT_PERMISSION_ID, readKernelModules, verifyKernelPermissionNonceAlignmentCalls } from "@oaath/sdk/kernel";
import { createPublicClient, http } from "cetane";
import { decodeEventLog, getAddress, getCreate2Address, keccak256 } from "cetane/utils";
import { entryPointAbi } from "@oaath/protocol";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
await assert.rejects(createLocalAnvilFixture({ chainIds: [] }), /local_fixture_chains_invalid/);
const providerCause = { code: -32500, message: "AA25 invalid account nonce" };
const classified = classifyUserOperationError({ stage: "send", error: providerCause });
assert.equal(classified.code, "nonce");
assert.equal(classified.retryable, false);
assert.equal(classified.cause, providerCause);
assert.equal(readUserOperationFailure(new Error("wrapped", { cause: classified })), classified);
assert.equal(readUserOperationFailure({ ...classified }), null);
const failed = createCetaneChainPorts({ 421614: { publicRpcUrls: ["https://fixture.test"], bundlerUrl: "https://fixture.test" } }, {
  retry: { attempts: 1 }, fetch: async () => new Response(null, { status: 503 }),
})[0];
await assert.rejects(failed.observation.read({ type: "user_operation_receipt", chainId: 421614, userOperationHash: "0x" + "11".repeat(32) }), error => error.failure?.stage === "receipt" && error.failure.code === "transport");
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
  const reader = createPublicClient({ chain: { id: 421614, name: "Anvil", nativeAA: false }, transport: http(fixture.rpcUrl(421614)) });
  assert.equal(await reader.getCode({ address: getCreate2Address({ from: factory, salt, bytecodeHash: keccak256(initCode) }) }), "0x6000");
  const receipt = await reader.getTransactionReceipt({ hash: deployed.transactionHash });
  const event = receipt.logs.map(log => { try { return decodeEventLog({ abi: entryPointAbi, ...log }); } catch { return null; } }).find(log => log?.eventName === "UserOperationEvent" && log.args.userOpHash === first.id);
  assert.ok(event);
  const reference = { chainId: 421614, entryPoint: kernelDeployment({ chainId: 421614 }).entryPoint.address, account: event.args.sender.toLowerCase(), nonce: event.args.nonce.toString(), userOperationHash: first.id };
  const inventory = await readKernelModules(reader, { address: reference.account, version: "4", budget: { maxRequests: 64, timeout: 5000 } });
  assert.equal(inventory.root?.status, "state-confirmed");
  assert.ok(inventory.validators.some(module => module.status === "state-confirmed"));
  assert.equal(inventory.permissions.length, 1);
  assert.match(inventory.permissions[0].id, /^0x[0-9a-f]{8}$/);
  assert.equal(inventory.permissions[0].status, "state-confirmed");
  assert.ok(inventory.permissions[0].policies.length >= 2);
  assert.ok(inventory.requests <= 64);
  assert.equal(inventory.complete, true);
  // An exhausted scan is not evidence that no other authority exists.
  const partial = await readKernelModules(reader, { address: reference.account, version: "4", blockNumber: inventory.blockNumber, budget: { maxRequests: 1, timeout: 5000 } });
  assert.equal(partial.complete, false);
  assert.equal(partial.reason, "budget");
  assert.equal(partial.requests, 1);
  const ports = () => createCetaneChainPorts({ 421614: {
    publicRpcUrls: [fixture.rpcUrl(421614)], headers: { "x-oaath-fixture": "observation" },
  } }, { maxRequests: 64, signal: new AbortController().signal, fetch: request => {
    assert.equal(request.headers.get("x-oaath-fixture"), "observation");
    return fetch(request);
  } });
  assert.deepEqual(ports()[0].routes, []);
  const beforeFinality = ports()[0].observation;
  const observer = createUserOperationObserver({
    read: request => beforeFinality.read(request.type === "finalized_block" ? { type: "canonical_block", chainId: 421614, blockNumber: "0" } : request),
    close: beforeFinality.close,
  });
  const observationInput = { reference: { ...reference, account: getAddress(reference.account), entryPoint: getAddress(reference.entryPoint) }, transactionHash: deployed.transactionHash, observedAt: Date.now(), timeoutMs: 10000 };
  const included = await observer.observeReference(observationInput);
  assert.equal(included.status, "included");
  assert.deepEqual(included.reference, reference);
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
import { type KernelModuleSnapshot, type KernelRuntime, kernelPermissionNonce, materializeKernelPermission, readKernelModules } from "@oaath/sdk/kernel";
export const inventory: (...input: Parameters<typeof readKernelModules>) => Promise<KernelModuleSnapshot> = readKernelModules;
import type { ObserveUserOperationResult } from "@oaath/sdk/advanced";
import { classifyUserOperationError, readUserOperationFailure } from "@oaath/sdk/cetane";
import type { UserOperationFailureCode } from "@oaath/sdk";
export const readFailure: typeof readUserOperationFailure = readUserOperationFailure;
export const classifiedCode: UserOperationFailureCode = classifyUserOperationError({ stage: "send", error: null }).code;
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
