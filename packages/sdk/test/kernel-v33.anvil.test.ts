import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSqliteOperationStoreAdapter } from "@oaath/testing";
import {
  concat,
  createWalletClient,
  custom,
  decodeEventLog,
  encodeFunctionData,
  getCreate2Address,
  type Hex,
  parseAbi,
  parseEther,
  toHex,
  zeroAddress,
  zeroHash,
} from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it } from "vitest";
import { createOAAth } from "../src/index.js";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import { createKernelV33Reads, kernelV33Deployment } from "../src/kernel/deployment/v33.js";
import { ecdsaKey, ecdsaWalletKey } from "../src/kernel/key/ecdsa.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { sessionOperator } from "../src/kernel/operator/session.js";
import {
  approveKernelV33Permission,
  kernelV33PermissionInstallNonce,
  materializeKernelV33Permission,
} from "../src/kernel/permission/v33.js";
import { KERNEL_V4_CREATE2_DEPLOYER } from "../src/kernel-v4.js";
import { createMemoryOperationStoreAdapter } from "../src/testing.js";
import { createViemChainPorts } from "../src/viem.js";
import { type AnvilChain, createHarness, startAnvil } from "./support/anvil.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
let chain: AnvilChain | undefined;
afterAll(() => chain?.stop());

(requireAnvil ? describe : describe.skip)("existing Kernel v3.3 / EntryPoint 0.7", () => {
  it("executes owner calls and scoped session calls at the same existing account", async () => {
    chain = await startAnvil(143, "prague", 1);
    const harness = await createHarness(chain);
    const deployment = kernelV33Deployment(143);
    const fixture = JSON.parse(
      await readFile(new URL("./fixtures/kernel-v33-deployments.json", import.meta.url), "utf8"),
    ) as {
      version: string;
      kernel: { address: Hex; deploymentInput: Hex };
      factory: { address: Hex; deploymentInput: Hex };
      ecdsaValidator: { address: Hex; deploymentInput: Hex };
    };
    expect(fixture.version).toBe("oaath.kernel-v33-deployments/v1");
    const entryPoint = JSON.parse(
      await readFile(
        new URL(`../node_modules/${harness.fixture.entryPoint.artifact}`, import.meta.url),
        "utf8",
      ),
    ) as { bytecode: Hex };
    await harness.deployCreate2(
      concat([harness.fixture.entryPoint.deploymentSalt, entryPoint.bytecode]),
    );
    for (const module of [fixture.kernel, fixture.factory, fixture.ecdsaValidator]) {
      expect(
        getCreate2Address({
          from: KERNEL_V4_CREATE2_DEPLOYER,
          salt: `0x${module.deploymentInput.slice(2, 66)}`,
          bytecode: `0x${module.deploymentInput.slice(66)}`,
        }).toLowerCase(),
      ).toBe(module.address);
      await harness.deployCreate2(module.deploymentInput);
    }
    expect(fixture.kernel.address).toBe(deployment.implementation);
    expect(fixture.factory.address).toBe(deployment.factory);
    expect(fixture.ecdsaValidator.address).toBe(deployment.ecdsaValidator);
    const owner = privateKeyToAccount(generatePrivateKey());
    const init = encodeFunctionData({
      abi: parseAbi([
        "function initialize(bytes21 rootValidator, address hook, bytes validatorData, bytes hookData, bytes[] initConfig)",
      ]),
      functionName: "initialize",
      args: [`0x01${deployment.ecdsaValidator.slice(2)}`, zeroAddress, owner.address, "0x", []],
    });
    const factoryAbi = parseAbi([
      "function createAccount(bytes data, bytes32 salt) returns (address)",
      "function getAddress(bytes data, bytes32 salt) view returns (address)",
    ]);
    const address = await harness.client.readContract({
      address: deployment.factory,
      abi: factoryAbi,
      functionName: "getAddress",
      args: [init, zeroHash],
    });
    const creation = await harness.wallet.writeContract({
      chain: null,
      address: deployment.factory,
      abi: factoryAbi,
      functionName: "createAccount",
      args: [init, zeroHash],
    });
    expect((await harness.client.waitForTransactionReceipt({ hash: creation })).status).toBe(
      "success",
    );
    await harness.fund(address, parseEther("1"));

    // The SDK is constructed only after the account already exists.
    const runtime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaKey({ account: owner, validator: deployment.ecdsaValidator }),
      }),
      reads: createKernelV33Reads(harness.client),
    });
    const bound = await runtime.bindAccount({ address });
    const target = privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Hex;
    const operation = runtime.prepareOperation({
      kind: "execution",
      grantId: "local-owner-operation",
      account: bound,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "7", data: "0x" }],
      gas: {
        callGasLimit: "200000",
        verificationGasLimit: "300000",
        preVerificationGas: "50000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    expect(operation.userOperation.sender).toBe(address.toLowerCase());
    expect(operation.userOperation.factory).toBeNull();
    const signature = await runtime.signOperation(operation);
    expect(signature.length).toBe(132);
    expect(await harness.sendSigned(operation, signature)).toBe("success");
    expect(await harness.client.getBalance({ address: target })).toBe(7n);
    // Observation and account recreation do not change ownership or deploy a new address.
    expect((await runtime.bindAccount({ address })).account).toBe(address.toLowerCase());

    let prompts = 0;
    const wallet = createWalletClient({
      account: owner.address,
      transport: custom({
        async request({ method, params }) {
          expect(method).toBe("personal_sign");
          const [digest, signer] = params as [Hex, Hex];
          expect(signer).toBe(owner.address.toLowerCase());
          prompts++;
          return owner.signMessage({ message: { raw: digest } });
        },
      }),
    });
    const connectedRuntime = createKernelRuntime({
      deployment,
      operator: ownerOperator({
        key: ecdsaWalletKey({ wallet, validator: deployment.ecdsaValidator }),
      }),
      reads: createKernelV33Reads(harness.client),
    });
    const next = connectedRuntime.prepareOperation({
      kind: "execution",
      grantId: "connected-owner-operation",
      account: await connectedRuntime.bindAccount({ address }),
      nonceKey: "0",
      sequence: "1",
      calls: [{ target, value: "11", data: "0x" }],
      gas: {
        callGasLimit: "200000",
        verificationGasLimit: "300000",
        preVerificationGas: "50000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    });
    expect(prompts).toBe(0);
    const connectedSignature = await connectedRuntime.signOperation(next);
    expect(prompts).toBe(1);
    expect(connectedSignature.length).toBe(132);
    expect(await harness.sendSigned(next, connectedSignature)).toBe("success");
    expect(await harness.client.getBalance({ address: target })).toBe(18n);

    const rpcUrl = chain.url;
    const receipts = new Map<string, unknown>();
    let directSends = 0;
    // The bundler supplies a fixed estimate. Account reads, signing, execution,
    // receipts and finality use the real contracts on the local chain.
    const ports = createViemChainPorts(
      { 143: { publicRpcUrls: [rpcUrl], bundlerUrl: "https://bundler.test" } },
      {
        maxRequests: 200,
        fetch: async (request) => {
          if (request.url.startsWith(rpcUrl)) return fetch(request);
          const { id, method, params } = await request.json();
          let result: unknown;
          if (method === "eth_chainId") result = "0x8f";
          else if (method === "eth_supportedEntryPoints") result = [deployment.entryPoint.address];
          else if (method === "eth_getUserOperationReceipt")
            result = receipts.get(params[0]) ?? null;
          else if (method === "eth_estimateUserOperationGas") {
            expect(params[0].nonce).toBe(toHex(2 + directSends));
            expect(params[0].factory).toBeUndefined();
            expect(params[0].signature.length).toBe(132);
            result = {
              callGasLimit: toHex(200000),
              verificationGasLimit: toHex(300000),
              preVerificationGas: toHex(50000),
            };
          } else if (method === "eth_sendUserOperation") {
            directSends++;
            const wire = params[0] as Record<string, string>;
            const operation = {
              ...wire,
              nonce: BigInt(wire.nonce!),
              callGasLimit: BigInt(wire.callGasLimit!),
              verificationGasLimit: BigInt(wire.verificationGasLimit!),
              preVerificationGas: BigInt(wire.preVerificationGas!),
              maxFeePerGas: BigInt(wire.maxFeePerGas!),
              maxPriorityFeePerGas: BigInt(wire.maxPriorityFeePerGas!),
            } as UserOperation<"0.7">;
            const hash = getUserOperationHash({
              userOperation: operation,
              entryPointAddress: deployment.entryPoint.address,
              entryPointVersion: "0.7",
              chainId: 143,
            });
            const transactionHash = await harness.wallet.sendTransaction({
              account: harness.submitter,
              chain: null,
              to: deployment.entryPoint.address,
              gas: 2_000_000n,
              data: encodeFunctionData({
                abi: entryPoint07Abi,
                functionName: "handleOps",
                args: [[toPackedUserOperation(operation)], harness.submitter.address],
              }),
            });
            const receipt = await harness.client.waitForTransactionReceipt({
              hash: transactionHash,
            });
            expect(receipt.status).toBe("success");
            const event = receipt.logs
              .map((log) => {
                try {
                  return decodeEventLog({
                    abi: entryPoint07Abi,
                    topics: log.topics,
                    data: log.data,
                  });
                } catch {
                  return null;
                }
              })
              .find((event) => event?.eventName === "UserOperationEvent");
            if (!event || event.eventName !== "UserOperationEvent")
              throw new Error("operation event missing");
            expect(event.args.success).toBe(true);
            receipts.set(hash, {
              userOpHash: hash,
              entryPoint: deployment.entryPoint.address,
              sender: operation.sender,
              nonce: toHex(operation.nonce),
              actualGasCost: toHex(event.args.actualGasCost),
              actualGasUsed: toHex(event.args.actualGasUsed),
              success: event.args.success,
              receipt: {
                transactionHash,
                blockHash: receipt.blockHash,
                blockNumber: toHex(receipt.blockNumber),
              },
            });
            await harness.client.request({
              method: "anvil_mine" as never,
              params: ["0x3"] as never,
            });
            result = hash;
          } else throw new Error("non-4337 request reached bundler");
          return Response.json({ jsonrpc: "2.0", id, result });
        },
      },
    );
    const client = createOAAth({
      mode: "owner",
      chains: ports,
      operations: createMemoryOperationStoreAdapter(),
    });
    try {
      const ownerHandle = client.account(address).owner(wallet);
      const calls = { chain: 143, calls: [{ target, value: "13", data: "0x" }] };
      expect(await ownerHandle.reviewCalls(calls)).toMatchObject({
        account: address.toLowerCase(),
        signer: "owner",
      });
      expect(prompts).toBe(1);
      const operation = await ownerHandle.sendCalls(calls);
      expect(prompts).toBe(2);
      expect((await operation.wait()).status).toBe("finalized");
      expect(directSends).toBe(1);
      expect(await harness.client.getBalance({ address: target })).toBe(31n);
      expect((await operation.receipt()).status).toBe("success");
      expect((await operation.execution()).route).toBe("bundler");
    } finally {
      await client.close();
    }

    // The default bundler port rejects once, then the connected owner EOA sends
    // the same bytes. Recreate every SDK/store instance before finalizing.
    const directory = await mkdtemp(join(tmpdir(), "oaath-direct-receipt-"));
    const filePath = join(directory, "operations.db");
    let eoaSends = 0;
    let rejectedSends = 0;
    let rejectedOperation: UserOperation<"0.7"> | undefined;
    await harness.fund(owner.address, parseEther("1"));
    const feeWallet = createWalletClient({
      account: owner.address,
      transport: custom({
        async request({ method, params }) {
          if (method === "eth_chainId") return "0x8f";
          if (method === "eth_accounts") return [owner.address];
          expect(method).toBe("eth_sendTransaction");
          const [transaction] = params as [
            { from: Hex; to: Hex; data: Hex; chainId: Hex; value: Hex },
          ];
          expect(transaction.from).toBe(owner.address.toLowerCase());
          expect(transaction.chainId).toBe("0x8f");
          expect(transaction.value).toBe("0x0");
          expect(rejectedOperation).toBeDefined();
          // Compare every packed field, including the unchanged owner signature.
          const expected = encodeFunctionData({
            abi: entryPoint07Abi,
            functionName: "handleOps",
            args: [[toPackedUserOperation(rejectedOperation!)], owner.address],
          });
          expect(transaction.data === expected).toBe(true);
          eoaSends++;
          return harness.wallet.sendTransaction({
            account: owner,
            chain: null,
            to: transaction.to,
            data: transaction.data,
            gas: 2_000_000n,
          });
        },
      }),
    });
    const direct = createOAAth({
      mode: "owner",
      operations: createSqliteOperationStoreAdapter(filePath),
      chains: createViemChainPorts(
        { 143: { publicRpcUrls: [rpcUrl], bundlerUrl: "https://rejecting-bundler.test" } },
        {
          fetch: async (request) => {
            if (request.url.startsWith(rpcUrl)) return fetch(request);
            const { id, method, params } = await request.json();
            let result: unknown;
            if (method === "eth_chainId") result = "0x8f";
            else if (method === "eth_supportedEntryPoints")
              result = [deployment.entryPoint.address];
            else if (method === "eth_estimateUserOperationGas")
              result = {
                callGasLimit: toHex(200000),
                verificationGasLimit: toHex(300000),
                preVerificationGas: toHex(50000),
              };
            else {
              expect(method).toBe("eth_sendUserOperation");
              rejectedSends++;
              const wire = params[0] as Record<string, string>;
              rejectedOperation = {
                ...wire,
                nonce: BigInt(wire.nonce!),
                callGasLimit: BigInt(wire.callGasLimit!),
                verificationGasLimit: BigInt(wire.verificationGasLimit!),
                preVerificationGas: BigInt(wire.preVerificationGas!),
                maxFeePerGas: BigInt(wire.maxFeePerGas!),
                maxPriorityFeePerGas: BigInt(wire.maxPriorityFeePerGas!),
              } as UserOperation<"0.7">;
              return Response.json({
                jsonrpc: "2.0",
                id,
                error: { code: -32500, message: "local refusal" },
              });
            }
            return Response.json({ jsonrpc: "2.0", id, result });
          },
        },
      ),
    });
    let saved: { chain: number; id: Hex };
    try {
      const request = {
        chain: 143,
        calls: [{ target, value: "17", data: "0x" }],
        feePayer: { kind: "connected-eoa", wallet: feeWallet },
      };
      const handle = direct.account(address).owner(wallet);
      expect(await handle.reviewCalls(request)).toMatchObject({
        route: "bundler",
        fallback: {
          route: "entrypoint-handleops",
          feePayer: owner.address.toLowerCase(),
          condition: "conclusive_bundler_rejection",
        },
      });
      expect(eoaSends).toBe(0);
      expect(prompts).toBe(2);
      const operation = await handle.sendCalls(request);
      saved = { chain: operation.chainId, id: operation.id };
      expect(operation.outcome.status).toBe("pending");
    } finally {
      await direct.close();
    }
    await harness.client.request({ method: "anvil_mine" as never, params: ["0x3"] as never });
    const recreated = createOAAth({
      mode: "owner",
      operations: createSqliteOperationStoreAdapter(filePath),
      chains: createViemChainPorts(
        { 143: { publicRpcUrls: [rpcUrl], bundlerUrl: "http://unused.test" } },
        {
          fetch: async (request) => {
            expect(new URL(request.url).hostname).not.toBe("unused.test");
            return fetch(request);
          },
        },
      ),
    });
    try {
      const recovered = await recreated.account(address).getOperation(saved);
      expect(recovered).not.toBeNull();
      expect((await recovered!.wait()).status).toBe("finalized");
      expect((await recovered!.receipt()).status).toBe("success");
      expect(await recovered!.execution()).toMatchObject({
        route: "entrypoint-handleops",
        id: saved.id,
        calls: [{ target, value: "17", data: "0x" }],
      });
      expect(eoaSends).toBe(1);
      expect(rejectedSends).toBe(1);
      expect(prompts).toBe(3);
      expect(await harness.client.getBalance({ address: target })).toBe(48n);
    } finally {
      await recreated.close();
      await rm(directory, { recursive: true, force: true });
    }

    for (const module of [
      harness.fixture.ecdsaSigner,
      harness.fixture.callPolicy,
      harness.fixture.validityPolicy,
      harness.fixture.rateLimitPolicy,
    ])
      await harness.deployModule(module);
    const sessionTarget = privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Hex;
    const sessionKey = ecdsaKey({
      account: privateKeyToAccount(generatePrivateKey()),
      validator: deployment.ecdsaValidator,
    });
    const now = Number((await harness.client.getBlock()).timestamp);
    const sessionRuntime = createKernelRuntime({
      deployment,
      operator: sessionOperator({
        key: sessionKey,
        policies: [
          {
            kind: "call",
            permissions: [{ target: sessionTarget, selector: "0x00000000", valueLimit: "5" }],
          },
          { kind: "expiry", validAfter: "0", validUntil: String(now + 600) },
          { kind: "operation-limit", maximumOperations: "2" },
        ],
      }),
      reads: createKernelV33Reads(harness.client),
    });
    const sessionAccount = await sessionRuntime.bindAccount({ address });
    if (sessionRuntime.validation.kind !== "permission")
      throw new Error("expected session permission");
    const nonce = await kernelV33PermissionInstallNonce({
      runtime: sessionRuntime,
      account: sessionAccount,
      reads: ports[0]!.reads,
    });
    expect(nonce).toBe("1");
    const approvalInput = {
      owner: ecdsaKey({ account: owner, validator: deployment.ecdsaValidator }),
      runtime: sessionRuntime,
      account: sessionAccount,
      nonce: nonce as string,
    };
    const sessionInput = {
      runtime: sessionRuntime,
      account: sessionAccount,
      grantId: "existing-v33-session",
      nonceKey: "0",
      sequence: "0",
      calls: [{ target: sessionTarget, value: "3", data: "0x" as const }],
      gas: {
        callGasLimit: "200000",
        verificationGasLimit: "300000",
        preVerificationGas: "50000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000",
      },
    };
    const wrongNonce = await materializeKernelV33Permission({
      ...sessionInput,
      approval: await approveKernelV33Permission({ ...approvalInput, nonce: "2" }),
    });
    expect((await harness.rejectionOf(wrongNonce.prepared, wrongNonce.signature)).errorName).toBe(
      "FailedOpWithRevert",
    );
    const enabled = await materializeKernelV33Permission({
      ...sessionInput,
      approval: await approveKernelV33Permission(approvalInput),
    });
    expect(enabled.prepared.userOperation.sender).toBe(address.toLowerCase());
    expect(enabled.prepared.userOperation.factory).toBeNull();
    expect(enabled.prepared.userOperation.verificationGasLimit).toBe("2000000");
    expect(await harness.sendSigned(enabled.prepared, enabled.signature)).toBe("success");
    expect(
      await kernelV33PermissionInstallNonce({
        runtime: sessionRuntime,
        account: sessionAccount,
        reads: createKernelV33Reads(harness.client),
      }),
    ).toBe("2");
    const { runtime: _runtime, ...standardInput } = sessionInput;
    const forbidden = sessionRuntime.prepareOperation({
      ...standardInput,
      kind: "execution",
      calls: [{ target, value: "1", data: "0x" }],
    });
    expect(
      (await harness.rejectionOf(forbidden, await sessionRuntime.signOperation(forbidden)))
        .errorName,
    ).toBe("FailedOpWithRevert");
    const subsequent = sessionRuntime.prepareOperation({ ...standardInput, kind: "execution" });
    expect(
      await harness.sendSigned(subsequent, await sessionRuntime.signOperation(subsequent)),
    ).toBe("success");
    expect(await harness.client.getBalance({ address: sessionTarget })).toBe(6n);
    const exhausted = sessionRuntime.prepareOperation({
      ...standardInput,
      kind: "execution",
      sequence: "1",
    });
    expect(
      (await harness.rejectionOf(exhausted, await sessionRuntime.signOperation(exhausted)))
        .errorName,
    ).toBe("FailedOpWithRevert");
  }, 30_000);
});
