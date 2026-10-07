/** The selected local weighted V09 validator and permission signer on real Kernel. */
import modules from "../packages/contracts/artifacts/KernelWeightedModules.json" with {
  type: "json",
};
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "weighted-root",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing"],
  files: {
    "run.mjs": `
import assert from "node:assert/strict";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { createKernelRuntime, kernelDeployment, kernelKey, ownerOperator, sessionOperator, approveKernelPermission, materializeKernelPermission, kernelPermissionNonce, readKernelModules } from "@oaath/sdk/kernel";
import { entryPointAbi, encodeKernelPermissionUninstallCalls } from "@oaath/protocol";
import { createPublicClient, createWalletClient, http } from "cetane";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { createExecution } from "cetane/execution/evm";
import { toPackedUserOperation } from "cetane/execution/erc4337";
import { encodeFunctionData, parseAbi, decodeEventLog, keccak256 } from "cetane/utils";
assert.throws(() => import.meta.resolve("viem"), { code: "ERR_MODULE_NOT_FOUND" });
const fixture = await createLocalOwnerAnvilFixture({ chainId: 143, kernelVersion: "0.4.0", owner: "p256" });
let ports;
try {
  const chain = { id: 143, name: "Local Anvil", nativeAA: false, execution: createExecution() };
  const reader = createPublicClient({ chain, transport: http(fixture.rpcUrl), pollingInterval: 25 });
  const payer = privateKeyToAccount(generatePrivateKey());
  await reader.request({ method: "anvil_setBalance", params: [payer.address, "0x56bc75e2d63100000"] });
  const wallet = createWalletClient({ chain, account: { address: payer.address }, signer: payer, transport: http(fixture.rpcUrl), pollingInterval: 25 });
  const deployment = kernelDeployment({ chainId: 143 });
  ports = fixture.createChainPorts()[0];
  const artifacts = ${JSON.stringify(modules)};
  for (const name of ["WeightedECDSAValidatorV09", "WeightedECDSASigner"]) {
    const artifact = artifacts[name];
    const hash = await wallet.sendTransaction({ to: deployment.create2Deployer, data: artifact.deploymentInput, gas: 8000000n });
    assert.equal((await reader.waitForTransactionReceipt({ hash })).status, "success");
    assert.ok((await reader.getCode({ address: artifact.expectedAddress })).length > 2);
  }
  const gas = { callGasLimit: "900000", verificationGasLimit: "3000000", preVerificationGas: "150000", maxFeePerGas: "2000000000", maxPriorityFeePerGas: "1000000000" };
  async function submit(prepared, signature) {
    try {
      const op = prepared.userOperation;
      const packed = toPackedUserOperation({ sender: op.sender, nonce: BigInt(op.nonce), callData: op.callData,
        callGasLimit: BigInt(op.callGasLimit), verificationGasLimit: BigInt(op.verificationGasLimit), preVerificationGas: BigInt(op.preVerificationGas),
        maxFeePerGas: BigInt(op.maxFeePerGas), maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas), signature }, "0.9");
      const hash = await wallet.sendTransaction({ to: deployment.entryPoint.address, gas: 8000000n,
        data: encodeFunctionData({ abi: entryPointAbi, functionName: "handleOps", args: [[packed], payer.address] }) });
      const receipt = await reader.waitForTransactionReceipt({ hash });
      assert.equal(receipt.status, "success");
      const event = receipt.logs.map(log => { try { return decodeEventLog({ abi: entryPointAbi, ...log }); } catch { return null; } })
        .find(event => event?.eventName === "UserOperationEvent" && event.args.userOpHash === prepared.userOperationHash);
      assert.equal(event?.args.success, true);
    } catch { throw new Error("weighted_operation_not_accepted"); }
  }
  const before = createKernelRuntime({ deployment, operator: ownerOperator({ key: fixture.ownerKey }), reads: ports.reads });
  const original = await before.bindAccount({ address: fixture.address });
  const accounts = Array.from({ length: 3 }, () => privateKeyToAccount(generatePrivateKey())).sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
  const guardians = accounts.map((account, index) => ({ address: account.address, weight: index === 1 ? 2 : 1 }));
  const signatureCounts = [0, 0, 0];
  const signers = accounts.slice(0, 2).map((account, index) => ({ address: account.address, sign: request => { signatureCounts[index]++; return account.sign(request); } }));
  const key = kernelKey({ kind: "weighted-ecdsa", guardians, threshold: 3, signers });
  const compose = () => createKernelRuntime({ deployment, operator: ownerOperator({ key }), reads: ports.reads });
  const setRoot = packages => encodeFunctionData({ abi: parseAbi(["function setRoot((uint256 moduleType, address module, bytes moduleData, bytes internalData)[] pkg, bool removeCurrent, bytes uninstallData)"]),
    functionName: "setRoot", args: [packages.map(pkg => ({ ...pkg, moduleType: BigInt(pkg.moduleType) })), true, "0x"] });
  function prepare(runtime, account, sequence, calls, kind = "execution") {
    return runtime.prepareOperation({ kind, grantId: "weighted-root-proof", account, nonceKey: "0", sequence, calls, gas });
  }
  async function execute(runtime, account, sequence, calls) {
    const op = prepare(runtime, account, sequence, calls);
    await submit(op, await runtime.signOperation(op));
  }
  await execute(before, original, "0", [{ target: fixture.address, value: "0", data: setRoot(compose().packages) }]);
  const runtime = compose();
  const imported = await runtime.bindAccount({ address: fixture.address });
  assert.deepEqual(signatureCounts, [0, 0, 0]);
  const target = "0x" + "78".repeat(20);
  await execute(runtime, imported, "1", [{ target, value: "11", data: "0x" }]);
  assert.equal(await reader.getBalance({ address: target }), 11n);
  assert.deepEqual(signatureCounts, [1, 1, 0]);
  const wrong = createKernelRuntime({ deployment, operator: ownerOperator({ key: kernelKey({ kind: "weighted-ecdsa", guardians, threshold: 2, signers }) }), reads: ports.reads });
  await assert.rejects(wrong.bindAccount({ address: fixture.address }), error => error.code === "kernel_runtime_binding_mismatch");
  assert.deepEqual(signatureCounts, [1, 1, 0]);
  const session = createKernelRuntime({ deployment, operator: sessionOperator({ key, policies: [{ kind: "call", permissions: [{ target, selector: "0x00000000", valueLimit: "5" }] }] }), reads: ports.reads });
  const account = await session.bindAccount({ address: fixture.address });
  const nonce = await kernelPermissionNonce({ runtime: session, account, reads: ports.reads, requestHash: keccak256("0x9876") });
  const approval = await approveKernelPermission({ owner: key, runtime: session, account, nonce });
  const enabled = await materializeKernelPermission({ runtime: session, approval, account, grantId: "weighted-session-proof", nonceKey: "0", sequence: "0", calls: [{ target, value: "5", data: "0x" }], gas });
  await submit(enabled.prepared, enabled.signature);
  assert.deepEqual(signatureCounts, [3, 3, 0]);
  const installed = await session.bindAccount({ address: fixture.address });
  await execute(session, installed, "0", [{ target, value: "5", data: "0x" }]);
  assert.equal(await reader.getBalance({ address: target }), 21n);
  const inventory = await readKernelModules(reader, { address: fixture.address, version: "4", budget: { maxRequests: 64, timeout: 5000 } });
  assert.ok(inventory.permissions.some(permission => permission.status === "state-confirmed"));
  const revoked = prepare(runtime, imported, "2", encodeKernelPermissionUninstallCalls({ account: fixture.address, packages: approval.packages }), "revocation");
  await submit(revoked, await runtime.signOperation(revoked));
  const count = [...signatureCounts];
  await assert.rejects(session.signOperation(prepare(session, installed, "1", [{ target, value: "5", data: "0x" }])), error => error.code === "kernel_runtime_binding_mismatch");
  assert.deepEqual(signatureCounts, count);
  // Uninstall/reinstall changes the epoch even when the public configuration is identical.
  const stale = prepare(runtime, imported, "5", [{ target, value: "1", data: "0x" }]);
  const staleSignature = await runtime.signOperation(stale);
  // Kernel forbids uninstalling the active root in place. Rotate to the
  // original P-256 authority, then install the same weighted configuration again.
  await execute(runtime, imported, "3", [{ target: fixture.address, value: "0", data: setRoot(before.packages) }]);
  const temporary = await before.bindAccount({ address: fixture.address });
  await execute(before, temporary, "4", [{ target: fixture.address, value: "0", data: setRoot(runtime.packages) }]);
  const afterEpoch = [...signatureCounts];
  await assert.rejects(runtime.signOperation(stale), error => error.code === "kernel_runtime_binding_mismatch");
  assert.deepEqual(signatureCounts, afterEpoch);
  await assert.rejects(submit(stale, staleSignature), /weighted_operation_not_accepted/);
  const reopened = compose();
  const recovered = await reopened.bindAccount({ address: fixture.address });
  await execute(reopened, recovered, "5", [{ target, value: "1", data: "0x" }]);
  assert.equal(await reader.getBalance({ address: target }), 22n);
  assert.equal(signatureCounts[2], 0);
  console.log("packed weighted root: 2-of-3 owner import/execution, quorum approval/revocation, weighted session enable/execution; epoch replay and stale signing refused");
} finally { await ports?.observation.close(); await fixture.close(); }
`,
    "surface.ts": `
import { kernelKey, type WeightedEcdsaGuardian, type EcdsaKeyAccount, type KeyOperationContext } from "@oaath/sdk/kernel";
export const weighted = (guardians: readonly WeightedEcdsaGuardian[], signers: readonly EcdsaKeyAccount[]) => kernelKey({ kind: "weighted-ecdsa", guardians, threshold: 2, signers });
export const epoch = (context: KeyOperationContext) => context.configurationEpoch;
`,
  },
});
try {
  consumer.typecheck();
  process.stdout.write(consumer.node("run.mjs"));
} finally {
  await consumer.cleanup();
}
