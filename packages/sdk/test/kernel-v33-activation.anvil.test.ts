import {
  concat,
  decodeErrorResult,
  encodeFunctionData,
  type Hex,
  parseAbi,
  parseEther,
  toHex,
  zeroAddress,
} from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it } from "vitest";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import { KERNEL_ENTRY_POINT_V07 } from "../src/kernel/deployment/v33.js";
import { ecdsaKey } from "../src/kernel/key/ecdsa.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { bindKernelAccount, createKernelReads, deriveKernelAccount } from "../src/kernel.js";
import { type AnvilChain, createHarness, startAnvil } from "./support/anvil.js";
import { deployKernelV33Contracts, deployKernelV33MetaFactory } from "./support/kernel-v33.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const chains: AnvilChain[] = [];
afterAll(() => {
  for (const chain of chains) chain.stop();
});

const gas = {
  callGasLimit: "200000",
  verificationGasLimit: "1500000",
  preVerificationGas: "100000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
};

(requireAnvil ? describe : describe.skip)("counterfactual Kernel v3.3 / EntryPoint 0.7", () => {
  it("activates the ZeroDev-derived account through the MetaFactory and fails closed on route drift", async () => {
    const chainId = 8453;
    const chain = await startAnvil(chainId);
    chains.push(chain);
    const harness = await createHarness(chain);
    const deployment = await deployKernelV33Contracts(harness, chainId);
    const reads = createKernelReads(harness.client);
    const owner = privateKeyToAccount(generatePrivateKey());
    const runtime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaKey({ account: owner, validator: deployment.ecdsaValidator }),
      }),
      reads,
    });
    const accountIndex = "5";

    // No MetaFactory, then an unapproved one: the route is unproven, so no descriptor.
    await expect(runtime.bindAccount({ accountIndex })).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    await deployKernelV33MetaFactory(harness, chainId, false);
    await expect(runtime.bindAccount({ accountIndex })).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    await deployKernelV33MetaFactory(harness, chainId, true);

    // Offline derivation equals the real factory's and EntryPoint's answers.
    const derived = deriveKernelAccount({ deployment, owner: owner.address, accountIndex });
    const initData = encodeFunctionData({
      abi: parseAbi([
        "function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
      ]),
      functionName: "initialize",
      args: [`0x01${deployment.ecdsaValidator.slice(2)}`, zeroAddress, owner.address, "0x", []],
    });
    const factoryAddress = await harness.client.readContract({
      address: deployment.factory,
      abi: parseAbi(["function getAddress(bytes data, bytes32 salt) view returns (address)"]),
      functionName: "getAddress",
      args: [initData, toHex(5n, { size: 32 })],
    });
    expect(factoryAddress.toLowerCase()).toBe(derived.address);
    const senderResponse = await fetch(chain.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [
          {
            to: KERNEL_ENTRY_POINT_V07.address,
            data: encodeFunctionData({
              abi: entryPoint07Abi,
              functionName: "getSenderAddress",
              args: [concat([derived.factory, derived.factoryData])],
            }),
          },
          "latest",
        ],
      }),
    });
    const senderError = decodeErrorResult({
      abi: entryPoint07Abi,
      data: ((await senderResponse.json()) as { error: { data: Hex } }).error.data,
    });
    expect(senderError.errorName).toBe("SenderAddressResult");
    expect(String(senderError.args[0]).toLowerCase()).toBe(derived.address);
    expect(await harness.client.getCode({ address: derived.address })).toBeUndefined();

    // Activation: the first owner operation carries the MetaFactory deployment.
    const account = await runtime.bindAccount({ accountIndex });
    expect(account).toMatchObject({ state: "counterfactual", account: derived.address });
    await harness.fund(derived.address, parseEther("1"));
    const target = privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Hex;
    const input = {
      account,
      kind: "execution" as const,
      grantId: "activation",
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "1", data: "0x" as const }],
      gas,
    };
    const activation = runtime.prepareOperation(input);
    expect(activation.userOperation).toMatchObject({
      sender: derived.address,
      factory: { address: deployment.metaFactory, data: derived.factoryData },
    });
    expect(await harness.sendSigned(activation, await runtime.signOperation(activation))).toBe(
      "success",
    );
    expect(await harness.client.getBalance({ address: target })).toBe(1n);

    // The deployed account binds through the existing-account path with this owner.
    const existing = await bindKernelAccount({
      chainId,
      address: derived.address,
      reads,
      deployment,
    });
    expect(existing).toMatchObject({
      state: "deployed",
      account: derived.address,
      rootValidator: `0x01${deployment.ecdsaValidator.slice(2)}`,
    });
    expect(
      await reads.read({ type: "kernel_ecdsa_owner", chainId, account: derived.address }),
    ).toBe(owner.address.toLowerCase());
    const rebound = await runtime.bindAccount({ accountIndex });
    expect(rebound).toEqual(existing);
    const next = runtime.prepareOperation({ ...input, account: rebound, sequence: "1" });
    expect(next.userOperation.factory).toBeNull();
    expect(await harness.sendSigned(next, await runtime.signOperation(next))).toBe("success");
    expect(await harness.client.getBalance({ address: target })).toBe(2n);

    // Factory code drift refuses another counterfactual account before signing.
    await harness.client.request({
      method: "anvil_setCode" as "eth_chainId",
      params: [deployment.factory, "0x6000"] as never,
    });
    await expect(runtime.bindAccount({ accountIndex: "6" })).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
  }, 60_000);
});
