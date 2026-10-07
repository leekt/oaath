/** Reviewed alternate implementation: real upgrade, bind and owner operation. */

import runtime from "../packages/contracts/artifacts/KernelV4Runtime.json" with { type: "json" };
import webauthnValidator from "../packages/contracts/artifacts/KernelWebAuthnValidator.json" with {
  type: "json",
};
import { createConsumer } from "./packed-consumer.mjs";

const consumer = await createConsumer({
  label: "kernel-import",
  packages: ["@oaath/protocol", "@oaath/sdk", "@oaath/server", "@oaath/testing"],
  files: {
    "run.mjs": `
import assert from "node:assert/strict";
import { createLocalOwnerAnvilFixture } from "@oaath/testing/anvil";
import { createOAAth } from "@oaath/sdk";
import { createKernelRuntime, kernelDeployment, kernelAccountDeployment, ownerOperator, kernelKey, sessionOperator, approveKernelPermission, materializeKernelPermission, kernelPermissionNonce, readKernelModules } from "@oaath/sdk/kernel";
import { createPublicClient, createWalletClient, http } from "cetane";
import { generatePrivateKey, privateKeyToAccount } from "cetane/accounts";
import { createExecution } from "cetane/execution/evm";
import { toPackedUserOperation } from "cetane/execution/erc4337";
import { encodeFunctionData, getCreate2Address, keccak256, parseAbi, bytesToHex, hexToBytes, concatHex, toHex, decodeEventLog } from "cetane/utils";
import { entryPointAbi, OAATH_OWNER_CREDENTIAL_PROFILE_VERSION, encodeKernelPermissionUninstallCalls } from "@oaath/protocol";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha256";
const hashBytes = value => bytesToHex(sha256(value));
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
    return submit(prepared, signature);
  }
  async function submit(prepared, signature) {
    const op = prepared.userOperation;
    const packed = toPackedUserOperation({ sender: op.sender, nonce: BigInt(op.nonce), callData: op.callData,
      callGasLimit: BigInt(op.callGasLimit), verificationGasLimit: BigInt(op.verificationGasLimit), preVerificationGas: BigInt(op.preVerificationGas),
      maxFeePerGas: BigInt(op.maxFeePerGas), maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas), signature }, "0.9");
    const hash = await wallet.sendTransaction({ to: base.entryPoint.address, gas: 8000000n,
      data: encodeFunctionData({ abi: entryPointAbi, functionName: "handleOps", args: [[packed], payer.address] }) });
    const receipt = await reader.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success");
    const event = receipt.logs.map(log => { try { return decodeEventLog({ abi: entryPointAbi, ...log }); } catch { return null; } })
      .find(event => event?.eventName === "UserOperationEvent" && event.args.userOpHash === prepared.userOperationHash);
    assert.equal(event?.args.success, true);
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
  // Rotate an existing account through its owner, then recreate its WebAuthn runtime.
  const module = ${JSON.stringify(webauthnValidator)};
  const moduleTx = await wallet.sendTransaction({ to: base.create2Deployer, data: module.deploymentInput, gas: 6000000n });
  assert.equal((await reader.waitForTransactionReceipt({ hash: moduleTx })).status, "success");
  assert.equal(keccak256(await reader.getCode({ address: module.expectedAddress })), module.runtimeCodeHash);
  const secret = p256.utils.randomPrivateKey();
  const publicKey = bytesToHex(p256.getPublicKey(secret, false));
  const credentialId = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64url");
  const credential = { version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION, kind: "webauthn", publicKey,
    authenticatorIdHash: keccak256(bytesToHex(Buffer.from(credentialId, "base64url"))) };
  const rpId = "app.example";
  const origin = "https://app.example";
  let assertions = 0;
  const passkey = kernelKey({ credential, credentialId, rpId, origin, authenticate: async ({ challenge }) => {
    assertions++;
    const clientDataJSON = JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false });
    const authenticatorData = concatHex([hashBytes(new TextEncoder().encode(rpId)), "0x05", "0x00000001"]);
    const digest = hashBytes(hexToBytes(concatHex([authenticatorData, hashBytes(new TextEncoder().encode(clientDataJSON))])));
    const signature = p256.sign(hexToBytes(digest), secret, { lowS: true, prehash: false });
    return { authenticatorData, clientDataJSON, responseTypeLocation: String(clientDataJSON.indexOf('"type":"webauthn.get"')),
      r: toHex(signature.r, { size: 32 }), s: toHex(signature.s, { size: 32 }) };
  } });
  const webauthn = () => createKernelRuntime({ deployment: profile, operator: ownerOperator({ key: passkey }), reads: ports.reads });
  const packages = webauthn().packages.map(pkg => ({ ...pkg, moduleType: BigInt(pkg.moduleType) }));
  await send(after, imported, "2", [{ target: fixture.address, value: "0", data: encodeFunctionData({
    abi: parseAbi(["function setRoot((uint256 moduleType, address module, bytes moduleData, bytes internalData)[] pkg, bool removeCurrent, bytes uninstallData)"]),
    functionName: "setRoot", args: [packages, true, "0x"],
  }) }]);
  const passkeyRuntime = webauthn();
  const passkeyAccount = await passkeyRuntime.bindAccount({ address: fixture.address });
  assert.equal(assertions, 0);
  const oldCount = fixture.signatureCount;
  await assert.rejects(after.bindAccount({ address: fixture.address }), error => error.code === "kernel_runtime_binding_mismatch");
  assert.equal(fixture.signatureCount, oldCount);
  await send(passkeyRuntime, passkeyAccount, "3", [{ target, value: "7", data: "0x" }]);
  assert.equal(await reader.getBalance({ address: target }), 130n);
  const sessionKey = kernelKey({ account: privateKeyToAccount(generatePrivateKey()), validator: module.expectedAddress });
  const session = createKernelRuntime({ deployment: profile, operator: sessionOperator({ key: sessionKey,
    policies: [{ kind: "call", permissions: [{ target, selector: "0x00000000", valueLimit: "5" }] }] }), reads: ports.reads });
  const sessionAccount = await session.bindAccount({ address: fixture.address });
  const nonce = await kernelPermissionNonce({ runtime: session, account: sessionAccount, reads: ports.reads, requestHash: keccak256("0x012345") });
  const approval = await approveKernelPermission({ owner: passkey, runtime: session, account: sessionAccount, nonce });
  const enabled = await materializeKernelPermission({ runtime: session, approval, account: sessionAccount, grantId: "webauthn-root-permission", nonceKey: "0", sequence: "0", calls: [{ target, value: "5", data: "0x" }], gas });
  await submit(enabled.prepared, enabled.signature);
  assert.equal(await reader.getBalance({ address: target }), 135n);
  const installed = await readKernelModules(reader, { address: fixture.address, version: "4", budget: { maxRequests: 64, timeout: 5000 } });
  assert.ok(installed.permissions.some(permission => permission.status === "state-confirmed"));
  const revoked = passkeyRuntime.prepareOperation({ kind: "revocation", grantId: "webauthn-root-permission", account: passkeyAccount, nonceKey: "0", sequence: "4",
    calls: encodeKernelPermissionUninstallCalls({ account: fixture.address, packages: approval.packages }), gas });
  await submit(revoked, await passkeyRuntime.signOperation(revoked));
  // The already-spent enable cannot restore authority. A standard session call fails.
  const later = session.prepareOperation({ kind: "execution", grantId: "webauthn-root-permission", account: sessionAccount, nonceKey: "0", sequence: "1", calls: [{ target, value: "5", data: "0x" }], gas });
  let rejected = false;
  try { await submit(later, await session.signOperation(later)); } catch { rejected = true; }
  assert.equal(rejected, true);
  assert.equal(await reader.getBalance({ address: target }), 135n);
  assert.equal(assertions, 3);
  // The default application path also accepts this owner. Return to its default
  // reviewed implementation so the caller need not inject a custom deployment.
  await send(passkeyRuntime, passkeyAccount, "5", [{ target: fixture.address, value: "0", data: encodeFunctionData({
    abi: parseAbi(["function upgradeToAndCall(address implementation, bytes data)"]), functionName: "upgradeToAndCall", args: [base.implementation, "0x"],
  }) }]);
  const app = createOAAth({ approvals: { kind: "wallet", owner: passkey }, account: fixture.address,
    chains: fixture.createChainPorts(), origin, stores: { kind: "memory" } });
  try {
    const grant = await (await app.connect()).requestPermission({ chainScope: "all", expiresIn: 3600, perChainOperationLimit: 3,
      permissions: [{ calls: [{ target, selectors: ["0x12345678"], valueLimit: "1" }] }] });
    const sent = await grant.sendCalls({ chain: 143, calls: [{ target, value: "1", data: "0x12345678" }] });
    assert.equal((await sent.wait({ attempts: 3 })).status, "finalized");
    assert.equal(await reader.getBalance({ address: target }), 136n);
  } finally { await app.close(); }
  console.log("packed Kernel import: reviewed implementation; WebAuthn root rotation/import, owner execution, session approval/materialization and revocation; unsupported root and wrong code refused before signing");
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
