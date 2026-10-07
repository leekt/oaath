/** Reviewed alternate implementation: real upgrade, bind and owner operation. */
import runtime from "../packages/contracts/artifacts/KernelV4Runtime.json" with { type: "json" };
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "kernel-import",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing"],
  files: {
    "run.mjs": `
import assert from "node:assert/strict";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { createKernelRuntime, kernelDeployment, kernelAccountDeployment, ownerOperator } from "@oaath/sdk/kernel";
import { createPublicClient, createWalletClient, http } from "cetane";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { createExecution } from "cetane/execution/evm";
import { toPackedUserOperation } from "cetane/execution/erc4337";
import { encodeFunctionData, getCreate2Address, keccak256, parseAbi } from "cetane/utils";
import { entryPointAbi } from "@oaath/protocol";
const fixture = await createLocalOwnerAnvilFixture({ chainId: 143, kernelVersion: "0.4.0", owner: "p256" });
let ports;
try {
  const chain = { id: 143, name: "Local Anvil", nativeAA: false, execution: createExecution() };
  const reader = createPublicClient({ chain, transport: http(fixture.rpcUrl), pollingInterval: 25 });
  const payer = privateKeyToAccount(generatePrivateKey());
  await reader.request({ method: "anvil_setBalance", params: [payer.address, "0x56bc75e2d63100000"] });
  const wallet = createWalletClient({ chain, account: { address: payer.address }, signer: payer, transport: http(fixture.rpcUrl), pollingInterval: 25 });
  const base = kernelDeployment({ chainId: 143 });
  // Same reviewed creation input, independently deployed under another salt.
  const bytecode = "0x" + ${JSON.stringify(runtime.kernelUups.deploymentInput)}.slice(66);
  const salt = "0x" + "b7".repeat(32);
  const implementation = getCreate2Address({ from: base.create2Deployer, salt, bytecodeHash: keccak256(bytecode) }).toLowerCase();
  const deployed = await wallet.sendTransaction({ to: base.create2Deployer, data: salt + bytecode.slice(2), gas: 10000000n });
  assert.equal((await reader.waitForTransactionReceipt({ hash: deployed })).status, "success");
  const code = await reader.getCode({ address: implementation });
  assert.ok(code && code !== "0x");
  const runtimeCodeHash = keccak256(code);
  ports = fixture.createChainPorts()[0];
  const before = createKernelRuntime({ deployment: base, operator: ownerOperator({ key: fixture.ownerKey }), reads: ports.reads });
  const original = await before.bindAccount({ address: fixture.address });
  const gas = { callGasLimit: "900000", verificationGasLimit: "3000000", preVerificationGas: "150000", maxFeePerGas: "2000000000", maxPriorityFeePerGas: "1000000000" };
  async function send(runtime, account, sequence, calls) {
    const prepared = runtime.prepareOperation({ kind: "execution", grantId: "reviewed-implementation-proof", account, nonceKey: "0", sequence, calls, gas });
    const signature = await runtime.signOperation(prepared);
    const op = prepared.userOperation;
    const packed = toPackedUserOperation({ sender: op.sender, nonce: BigInt(op.nonce), callData: op.callData,
      callGasLimit: BigInt(op.callGasLimit), verificationGasLimit: BigInt(op.verificationGasLimit), preVerificationGas: BigInt(op.preVerificationGas),
      maxFeePerGas: BigInt(op.maxFeePerGas), maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas), signature }, "0.9");
    const hash = await wallet.sendTransaction({ to: base.entryPoint.address, gas: 8000000n,
      data: encodeFunctionData({ abi: entryPointAbi, functionName: "handleOps", args: [[packed], payer.address] }) });
    assert.equal((await reader.waitForTransactionReceipt({ hash })).status, "success");
  }
  await send(before, original, "0", [{ target: fixture.address, value: "0", data: encodeFunctionData({
    abi: parseAbi(["function upgradeToAndCall(address implementation, bytes data)"]), functionName: "upgradeToAndCall", args: [implementation, "0x"],
  }) }]);
  const signatures = fixture.signatureCount;
  await assert.rejects(before.bindAccount({ address: fixture.address }), error => error.code === "kernel_runtime_binding_mismatch");
  const wrong = createKernelRuntime({ deployment: kernelDeployment({ chainId: 143, reviewedImplementations: [{ address: implementation, runtimeCodeHash: "0x" + "00".repeat(32) }] }),
    operator: ownerOperator({ key: fixture.ownerKey }), reads: ports.reads });
  await assert.rejects(wrong.bindAccount({ address: fixture.address }), error => error.code === "kernel_runtime_evidence_invalid");
  assert.equal(fixture.signatureCount, signatures);
  const profile = kernelDeployment({ chainId: 143, reviewedImplementations: [{ address: implementation, runtimeCodeHash }] });
  const after = createKernelRuntime({ deployment: profile, operator: ownerOperator({ key: fixture.ownerKey }), reads: ports.reads });
  const imported = await after.bindAccount({ address: fixture.address });
  assert.equal(imported.implementation, implementation);
  assert.equal(kernelAccountDeployment(imported), profile);
  const target = "0x" + "67".repeat(20);
  await send(after, imported, "1", [{ target, value: "123", data: "0x" }]);
  assert.equal(await reader.getBalance({ address: target }), 123n);
  console.log("packed Kernel import: reviewed alternate implementation, accepted owner upgrade/execution; unreviewed address and wrong runtime hash refused before signing");
} finally { await ports?.observation.close(); await fixture.close(); }
`,
    "surface.ts": `
import { kernelDeployment, type ReviewedKernelImplementation } from "@oaath/sdk/kernel";
export function reviewed(chainId: number, implementations: readonly ReviewedKernelImplementation[]) {
  return kernelDeployment({ chainId, reviewedImplementations: implementations });
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
