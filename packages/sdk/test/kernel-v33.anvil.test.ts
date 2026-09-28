import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSqliteOperationStoreAdapter } from "@oaath/testing";
import {
  concat,
  createWalletClient,
  custom,
  decodeAbiParameters,
  decodeEventLog,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  http,
  parseEther,
  toHex,
} from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it, vi } from "vitest";
import { createOAAth } from "../src/index.js";
import { createKernelRuntime } from "../src/kernel/create-kernel-runtime.js";
import { createKernelV33Reads, kernelV33Deployment } from "../src/kernel/deployment/v33.js";
import { kernelV33OperationSigningHash } from "../src/kernel/deployment/v33-operation.js";
import { ecdsaKey, ecdsaWalletKey } from "../src/kernel/key/ecdsa.js";
import { ownerOperator } from "../src/kernel/operator/owner.js";
import { sessionOperator } from "../src/kernel/operator/session.js";
import {
  approveKernelV33Permission,
  kernelV33PermissionInstallNonce,
  materializeKernelV33Permission,
  parseKernelV33PermissionApproval,
} from "../src/kernel/permission/v33.js";
import {
  kernelV33EffectivePermissionNonce,
  kernelV33PermissionRevocationCalls,
  kernelV33PermissionStatus,
  parseKernelV33PermissionState,
} from "../src/kernel/permission/v33-revocation.js";
import { createMemoryOperationStoreAdapter } from "../src/testing.js";
import { createViemChainPorts } from "../src/viem.js";
import { type AnvilChain, createHarness, startAnvil } from "./support/anvil.js";
import { deployKernelV33Account } from "./support/kernel-v33.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const chains: AnvilChain[] = [];
afterAll(() => {
  for (const chain of chains) chain.stop();
});

async function setupV33(chainId: number, owner: ReturnType<typeof privateKeyToAccount>) {
  const chain = await startAnvil(chainId, "prague", 1);
  chains.push(chain);
  const harness = await createHarness(chain);
  const { deployment, address } = await deployKernelV33Account(harness, chainId, owner.address);

  return { chain, harness, deployment, address };
}

(requireAnvil ? describe : describe.skip)("existing Kernel v3.3 / EntryPoint 0.7", () => {
  it("uses one owner approval on two chains and keeps EntryPoint identities chain-specific", async () => {
    const owner = privateKeyToAccount(generatePrivateKey());
    const ownerSign = vi.fn(owner.sign.bind(owner));
    const sessionKey = ecdsaKey({
      account: privateKeyToAccount(generatePrivateKey()),
      validator: kernelV33Deployment(143).ecdsaValidator,
    });
    const target = privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Hex;
    let approval: Awaited<ReturnType<typeof approveKernelV33Permission>> | undefined;
    const operationHashes: Hex[] = [];
    const signingHashes: Hex[] = [];
    let existingAddress: string | undefined;
    for (const chainId of [143, 480]) {
      const { harness, address, deployment } = await setupV33(chainId, owner);
      existingAddress ??= address;
      expect(address).toBe(existingAddress);
      for (const module of [harness.fixture.ecdsaSigner, harness.fixture.callPolicy])
        await harness.deployModule(module);
      const reads = createKernelV33Reads(harness.client);
      const runtime = createKernelRuntime({
        deployment,
        reads,
        operator: sessionOperator({
          key: sessionKey,
          policies: [
            { kind: "call", permissions: [{ target, selector: "0x00000000", valueLimit: "5" }] },
          ],
        }),
      });
      const account = await runtime.bindAccount({ address });
      const nonce = await kernelV33PermissionInstallNonce({ runtime, account, reads });
      expect(nonce).toBe("1");
      approval ??= await approveKernelV33Permission({
        owner: ecdsaKey({
          account: { address: owner.address, sign: ownerSign },
          validator: deployment.ecdsaValidator,
        }),
        runtime,
        account,
        nonce,
      });
      // Recreate the approval from persisted JSON before using it on either chain.
      const restored = parseKernelV33PermissionApproval(JSON.parse(JSON.stringify(approval)));
      const input = {
        runtime,
        account,
        grantId: "same-v33-grant",
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "3", data: "0x" as const }],
        gas: {
          callGasLimit: "200000",
          verificationGasLimit: "2000000",
          preVerificationGas: "50000",
          maxFeePerGas: "2000000000",
          maxPriorityFeePerGas: "1000000000",
        },
      };
      const enabled = await materializeKernelV33Permission({ ...input, approval: restored });
      operationHashes.push(enabled.prepared.userOperationHash);
      signingHashes.push(kernelV33OperationSigningHash(enabled.prepared));
      // A normal chain-specific key signature cannot replace the replayable one.
      const parameters = [
        { type: "bytes" },
        { type: "bytes" },
        { type: "bytes" },
        { type: "bytes" },
        { type: "bytes" },
      ] as const;
      const envelope = decodeAbiParameters(parameters, `0x${enabled.signature.slice(106)}`);
      const wrongSignature = concat([
        enabled.signature.slice(0, 106) as Hex,
        encodeAbiParameters(parameters, [
          envelope[0],
          envelope[1],
          envelope[2],
          envelope[3],
          concat(["0xff", await sessionKey.sign(enabled.prepared.userOperationHash)]),
        ]),
      ]);
      expect((await harness.rejectionOf(enabled.prepared, wrongSignature)).errorName).toBe(
        "FailedOp",
      );
      expect(await harness.sendSigned(enabled.prepared, enabled.signature)).toBe("success");
      const { runtime: _runtime, ...standardInput } = input;
      const installed = runtime.prepareOperation({ ...standardInput, kind: "execution" });
      expect(kernelV33OperationSigningHash(installed)).toBe(installed.userOperationHash);
      expect(await harness.sendSigned(installed, await runtime.signOperation(installed))).toBe(
        "success",
      );
      expect(await harness.client.getBalance({ address: target })).toBe(6n);
      const consumedApproval = await materializeKernelV33Permission({
        ...input,
        sequence: "1",
        approval: restored,
      });
      expect(
        (await harness.rejectionOf(consumedApproval.prepared, consumedApproval.signature))
          .errorName,
      ).toBe("FailedOpWithRevert");
    }
    expect(ownerSign).toHaveBeenCalledTimes(1);
    expect(operationHashes[0]).not.toBe(operationHashes[1]);
    expect(signingHashes[0]).toBe(signingHashes[1]);
  }, 30_000);

  it("revokes installed and unused approvals without disabling another permission", async () => {
    const ownerAccount = privateKeyToAccount(generatePrivateKey());
    const { harness, address, deployment } = await setupV33(143, ownerAccount);
    for (const module of [harness.fixture.ecdsaSigner, harness.fixture.callPolicy])
      await harness.deployModule(module);
    const reads = createKernelV33Reads(harness.client);
    const ownerKey = ecdsaKey({ account: ownerAccount, validator: deployment.ecdsaValidator });
    const owner = createKernelRuntime({
      deployment,
      reads,
      operator: ownerOperator({ key: ownerKey }),
    });
    const account = await owner.bindAccount({ address });
    const target = privateKeyToAccount(generatePrivateKey()).address.toLowerCase() as Hex;
    const gas = {
      callGasLimit: "900000",
      verificationGasLimit: "2000000",
      preVerificationGas: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
    };
    async function permission(grantId: string) {
      const runtime = createKernelRuntime({
        deployment,
        reads,
        operator: sessionOperator({
          key: ecdsaKey({
            account: privateKeyToAccount(generatePrivateKey()),
            validator: deployment.ecdsaValidator,
          }),
          policies: [
            { kind: "call", permissions: [{ target, selector: "0x00000000", valueLimit: "1" }] },
          ],
        }),
      });
      const descriptor = await runtime.bindAccount({ address });
      const approval = await approveKernelV33Permission({
        runtime,
        account: descriptor,
        owner: ownerKey,
        nonce: "1",
      });
      const input = {
        runtime,
        account: descriptor,
        approval,
        grantId,
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "1", data: "0x" as const }],
        gas,
      };
      return { input, runtime, approval };
    }
    const survivor = await permission("survivor");
    const installed = await permission("installed");
    const unused = await permission("unused");
    for (const permission of [survivor, installed]) {
      const enabled = await materializeKernelV33Permission(permission.input);
      expect(await harness.sendSigned(enabled.prepared, enabled.signature)).toBe("success");
    }
    for (const [sequence, permission] of [installed, unused].entries()) {
      const state = parseKernelV33PermissionState(
        await reads.read({
          type: "kernel_v33_permission_state",
          chainId: 143,
          account: address,
          permissionId: permission.approval.permissionId,
        }),
      );
      const calls = kernelV33PermissionRevocationCalls({ approval: permission.approval, state });
      expect(calls.length).toBe(sequence === 0 ? 1 : 2);
      const prepared = owner.prepareOperation({
        kind: "revocation",
        grantId: permission.input.grantId,
        account,
        nonceKey: "0",
        sequence: sequence.toString(),
        calls,
        gas,
      });
      expect(await harness.sendSigned(prepared, await owner.signOperation(prepared))).toBe(
        "success",
      );
      const after = parseKernelV33PermissionState(
        await reads.read({
          type: "kernel_v33_permission_state",
          chainId: 143,
          account: address,
          permissionId: permission.approval.permissionId,
        }),
      );
      expect(kernelV33PermissionStatus(after, permission.approval)).toBe("absent");
      expect(
        BigInt(kernelV33EffectivePermissionNonce(after)) > BigInt(permission.approval.nonce),
      ).toBe(true);
      expect(
        kernelV33PermissionRevocationCalls({ approval: permission.approval, state: after }),
      ).toHaveLength(0);
      const replay = await materializeKernelV33Permission({
        ...permission.input,
        sequence: sequence === 0 ? "1" : "0",
      });
      expect((await harness.rejectionOf(replay.prepared, replay.signature)).errorName).toBe(
        "FailedOpWithRevert",
      );
      const { runtime: _runtime, approval: _approval, ...operation } = permission.input;
      const standard = permission.runtime.prepareOperation({ ...operation, kind: "execution" });
      expect(
        (await harness.rejectionOf(standard, await permission.runtime.signOperation(standard)))
          .errorName,
      ).toBe("FailedOpWithRevert");
    }
    const { runtime: _runtime, approval: _approval, ...operation } = survivor.input;
    const standard = survivor.runtime.prepareOperation({ ...operation, kind: "execution" });
    expect(await harness.sendSigned(standard, await survivor.runtime.signOperation(standard))).toBe(
      "success",
    );
    expect(await harness.client.getBalance({ address: target })).toBe(3n);
  }, 30_000);

  it.each(["browser", "local"])(
    "executes owner calls and scoped session calls with a %s wallet",
    async (walletKind) => {
      const owner = privateKeyToAccount(generatePrivateKey());
      const { chain, harness, deployment, address } = await setupV33(143, owner);

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
            else if (method === "eth_supportedEntryPoints")
              result = [deployment.entryPoint.address];
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
      const browserFeeWallet = createWalletClient({
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
      const localWallet = createWalletClient({
        account: owner,
        transport: http(rpcUrl, { retryCount: 0 }),
      });
      const feeWallet =
        walletKind === "browser"
          ? browserFeeWallet
          : {
              ...localWallet,
              async sendTransaction(input: Parameters<typeof localWallet.sendTransaction>[0]) {
                const expected = encodeFunctionData({
                  abi: entryPoint07Abi,
                  functionName: "handleOps",
                  args: [[toPackedUserOperation(rejectedOperation!)], owner.address],
                });
                expect(input.data === expected).toBe(true);
                eoaSends++;
                return localWallet.sendTransaction({ ...input, gas: 2_000_000n });
              },
            };
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
        const handle = direct
          .account(address)
          .owner(walletKind === "browser" ? wallet : localWallet);
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
        expect(prompts).toBe(walletKind === "browser" ? 3 : 2);
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
    },
    30_000,
  );
});
