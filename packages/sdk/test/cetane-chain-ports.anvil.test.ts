import { createServer } from "node:http";
import {
  OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
  type UserOperationReference,
} from "@oaath/protocol";
import { IDBFactory } from "fake-indexeddb";
import {
  createWalletClient,
  custom,
  decodeEventLog,
  encodeFunctionData,
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
import { describe, expect, it } from "vitest";
import { createUserOperationObserver, type OaathUsageRequest } from "../src/advanced.js";
import { createCetaneChainPorts } from "../src/cetane.js";
import { grantProviderPort } from "../src/client/grant-handle.js";
import { createOAAth, type Oaath } from "../src/index.js";
import { kernelDeployment } from "../src/kernel.js";
import { createIndexedDbCleanupStore } from "../src/persistence/indexeddb/cleanup-store.js";
import { createIndexedDbContextStore } from "../src/persistence/indexeddb/context-store.js";
import { openOaathDatabase } from "../src/persistence/indexeddb/database.js";
import { createIndexedDbGrantStoreAdapter } from "../src/persistence/indexeddb/grant-store.js";
import { createIndexedDbKeyStore } from "../src/persistence/indexeddb/key-store.js";
import { createIndexedDbOperationStoreAdapter } from "../src/persistence/indexeddb/operation-store.js";
import { createIndexedDbPreparedCallStoreAdapter } from "../src/persistence/indexeddb/prepared-call-store.js";
import { createIndexedDbWalletCallBundleStoreAdapter } from "../src/persistence/indexeddb/wallet-call-bundle-store.js";
import { createHarness, deployKernelStack, startAnvil } from "./support/anvil.js";
import {
  bindingInput,
  CHAIN_ID,
  createClock,
  createRealm,
  ownerCredential,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";
import { deployKernelV33Account } from "./support/kernel-v33.js";

describe.skipIf(process.env.OAATH_REQUIRE_ANVIL !== "1")(
  "default ports against a real local chain",
  () => {
    it.each([
      ["0.4.0", "issuer"],
      ["0.3.3", "issuer"],
      ["0.3.3", "local"],
    ] as const)(
      "Kernel %s %s Grant recovers a lost enable reply after reload and executes the installed session",
      async (version, mode) => {
        const local = await startAnvil(CHAIN_ID, "prague", 1);
        const harness = await createHarness(local);
        const deployment = kernelDeployment({ chainId: CHAIN_ID, kernelVersion: version });
        const clock = createClock(Math.floor(Date.now() / 1000));
        let realm: { oaath: Readonly<Oaath> } | undefined;
        const ownerAccount = privateKeyToAccount(generatePrivateKey());
        const ownerOffset = mode === "local" ? 1 : 0;
        let approvalPrompts = 0;
        let ownerOperationPrompts = 0;
        const wallet = createWalletClient({
          account: ownerAccount.address,
          transport: custom({
            async request({ method, params }) {
              if (method === "eth_signTypedData_v4") {
                approvalPrompts += 1;
                const [signer, payload] = params as [string, string];
                expect(signer.toLowerCase()).toBe(ownerAccount.address.toLowerCase());
                return ownerAccount.signTypedData(JSON.parse(payload));
              }
              if (method === "personal_sign") {
                ownerOperationPrompts += 1;
                const [raw, signer] = params as [`0x${string}`, string];
                expect(signer.toLowerCase()).toBe(ownerAccount.address.toLowerCase());
                return ownerAccount.signMessage({ message: { raw } });
              }
              throw new Error("unexpected wallet request");
            },
          }),
        });
        const factory = new IDBFactory();
        let database = await openOaathDatabase({ factory });
        function stores() {
          return {
            grants: createIndexedDbGrantStoreAdapter(database),
            operations: createIndexedDbOperationStoreAdapter(database),
            keys: createIndexedDbKeyStore(database),
            context: createIndexedDbContextStore(database),
            cleanup: createIndexedDbCleanupStore(database),
            walletCallBundles: createIndexedDbWalletCallBundleStoreAdapter(database),
            preparedCallContexts: createIndexedDbPreparedCallStoreAdapter(database),
          };
        }
        const modeBytes: bigint[] = [];
        const receipts = new Map<string, unknown>();
        const references = new Map<string, Readonly<UserOperationReference>>();
        const methods: string[] = [];
        let sends = 0;
        let estimates = 0;
        let usageRequest: OaathUsageRequest | undefined;
        let usageError: string | null = null;
        // Only the 4337 facade is a fixture. Factory/account/nonce/fee/policy reads,
        // execution, receipts, canonical blocks and finality come from Anvil.
        const server = createServer(async (request, response) => {
          if (request.url === "/unavailable") {
            response.writeHead(502).end("bad gateway");
            return;
          }
          let id: unknown;
          try {
            let body = "";
            for await (const chunk of request) body += String(chunk);
            const rpc = JSON.parse(body) as { id: number; method: string; params: unknown[] };
            id = rpc.id;
            methods.push(rpc.method);
            let result: unknown;
            if (rpc.method === "eth_chainId") result = toHex(CHAIN_ID);
            else if (rpc.method === "eth_supportedEntryPoints")
              result = [deployment.entryPoint.address];
            else if (rpc.method === "eth_getUserOperationReceipt")
              result = receipts.get(String(rpc.params[0])) ?? null;
            else if (rpc.method === "eth_estimateUserOperationGas") {
              estimates += 1;
              const op = rpc.params[0] as Record<string, string>;
              expect(typeof op.signature === "string" && op.signature.length >= 132).toBe(true);
              expect(op.factory !== undefined).toBe(version === "0.4.0" && sends === 0);
              result = {
                callGasLimit: "0xdbba0",
                verificationGasLimit: "0x2dc6c0",
                preVerificationGas: "0x249f0",
              };
            } else if (rpc.method === "eth_sendUserOperation") {
              sends += 1;
              const wire = rpc.params[0] as Record<string, string>;
              modeBytes.push(BigInt(wire.nonce!) >> 248n);
              const operation = {
                ...wire,
                nonce: BigInt(wire.nonce!),
                callGasLimit: BigInt(wire.callGasLimit!),
                verificationGasLimit: BigInt(wire.verificationGasLimit!),
                preVerificationGas: BigInt(wire.preVerificationGas!),
                maxFeePerGas: BigInt(wire.maxFeePerGas!),
                maxPriorityFeePerGas: BigInt(wire.maxPriorityFeePerGas!),
              } as UserOperation<"0.9">;
              const hash = getUserOperationHash({
                userOperation: operation,
                entryPointAddress: deployment.entryPoint.address,
                entryPointVersion: deployment.entryPoint.version,
                chainId: CHAIN_ID,
              });
              references.set(
                hash,
                Object.freeze({
                  chainId: CHAIN_ID,
                  entryPoint: deployment.entryPoint.address,
                  account: operation.sender.toLowerCase() as `0x${string}`,
                  nonce: String(operation.nonce),
                  userOperationHash: hash,
                }),
              );
              const transactionHash = await harness.wallet.sendTransaction({
                account: harness.submitter,
                chain: null,
                to: deployment.entryPoint.address,
                gas: 8_000_000n,
                data: encodeFunctionData({
                  abi: entryPoint07Abi,
                  functionName: "handleOps",
                  args: [[toPackedUserOperation(operation)], harness.submitter.address],
                }),
              });
              const receipt = await harness.client.waitForTransactionReceipt({
                hash: transactionHash,
              });
              if (receipt.status !== "success") throw new Error("local operation failed");
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
                throw new Error("local operation event missing");
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
              if (
                sends === 1 ||
                sends === 1 + ownerOffset ||
                (version === "0.3.3" && (sends === 3 + ownerOffset || sends === 4 + ownerOffset))
              ) {
                // Acceptance happened, but the response is lost. Observation is
                // the only recovery; the transport must not send again.
                response.writeHead(502).end("lost reply");
                return;
              }
              await harness.client.request({
                method: "anvil_mine" as never,
                params: ["0x3"] as never,
              });
              result = hash;
            } else throw new Error("ordinary RPC reached bundler");
            response.setHeader("content-type", "application/json");
            response.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
          } catch {
            response.setHeader("content-type", "application/json");
            response.end(
              JSON.stringify({
                jsonrpc: "2.0",
                id,
                error: { code: -32603, message: "local facade failed" },
              }),
            );
          }
        });
        try {
          const existing =
            version === "0.3.3"
              ? await deployKernelV33Account(
                  harness,
                  CHAIN_ID,
                  mode === "local" ? ownerAccount.address : ownerCredential.address,
                )
              : null;
          if (existing === null) await deployKernelStack(harness);
          for (const module of [
            harness.fixture.ecdsaSigner,
            harness.fixture.callPolicy,
            harness.fixture.validityPolicy,
            harness.fixture.rateLimitPolicy,
          ])
            await harness.deployModule(module);
          const validator =
            existing?.deployment.ecdsaValidator ?? (await harness.deployValidatorCreate2());
          await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
          const endpoint = server.address();
          if (!endpoint || typeof endpoint === "string") throw new Error("local RPC unavailable");
          const url = `http://127.0.0.1:${endpoint.port}`;
          let rpcRequests = 0;
          const allowedEndpoints = new Set(
            [url, `${url}/unavailable`, local.url].map((value) => new URL(value).href),
          );
          const chainPorts = () =>
            createCetaneChainPorts(
              { [CHAIN_ID]: { publicRpcUrls: [`${url}/unavailable`, local.url], bundlerUrl: url } },
              {
                retry: { attempts: 2, delayMs: 0 },
                maxRequests: 300,
                async fetch(request) {
                  if (!allowedEndpoints.has(request.url))
                    throw new Error("only owned RPC endpoints are allowed");
                  rpcRequests++;
                  return fetch(request);
                },
              },
            );
          let ports = chainPorts()[0];
          if (!ports) throw new Error("chain missing");
          const binding =
            existing === null
              ? bindingInput
              : {
                  ...bindingInput,
                  account: {
                    version: OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
                    kind: "kernel",
                    kernelVersion: "0.3.3",
                    address: existing.address.toLowerCase(),
                    entryPoint: { version: "0.7" },
                    ownerCredential,
                  },
                };
          function newRealm() {
            if (mode === "local") {
              if (!existing || !ports) throw new Error("local account unavailable");
              return {
                oaath: createOAAth({
                  approvals: { kind: "wallet", owner: wallet },
                  account: existing.address,
                  chains: [
                    {
                      ...ports,
                      usage: async (request: Readonly<OaathUsageRequest>) => {
                        usageRequest = request;
                        try {
                          return await ports!.usage!(request);
                        } catch (error) {
                          usageError = (error as { code?: string }).code ?? "unclassified";
                          throw error;
                        }
                      },
                    },
                  ],
                  stores: { kind: "indexeddb", factory },
                  origin: "https://local.example",
                  now: clock.now,
                }),
              };
            }
            return createRealm({
              binding,
              stores: stores(),
              validator,
              clock,
              chain: {
                capability: {
                  ...ports!,
                  usage: async (request: Readonly<OaathUsageRequest>) => {
                    usageRequest = request;
                    try {
                      return await ports!.usage!(request);
                    } catch (error) {
                      usageError = (error as { code?: string }).code ?? "unclassified";
                      throw error;
                    }
                  },
                },
                sends: [],
                signatures: [],
                quotes: 0,
              },
            });
          }
          async function reopenGrant() {
            if (!realm) throw new Error("realm unavailable");
            await realm.oaath.close();
            database.close();
            database = await openOaathDatabase({ factory });
            ports = chainPorts()[0];
            if (!ports) throw new Error("chain missing");
            realm = newRealm();
            const restored = await (await realm.oaath.connect()).resume();
            if (restored === null) throw new Error("Grant was not restored");
            return restored;
          }
          realm = newRealm();
          let grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
          expect(approvalPrompts).toBe(mode === "local" ? 1 : 0);
          const address = await grant.account(CHAIN_ID);
          if (existing !== null) expect(address).toBe(existing.address.toLowerCase());
          if (version === "0.3.3") {
            const provider = grantProviderPort(grant);
            expect(await provider.probeValidityTimeRangeSupport(CHAIN_ID)).toEqual({
              status: "unsupported",
            });
            expect(grant.state).toBe("active");
            expect(sends).toBe(0);
          }
          await harness.fund(await grant.account(CHAIN_ID), parseEther("1"));
          await harness.client.request({ method: "anvil_mine" as never, params: ["0x3"] as never });
          if (mode === "local") {
            const calls = { ...(sendCallsInput() as Record<string, unknown>), signer: "auto" };
            const ownerReview = await grant.reviewCalls(calls);
            expect(ownerReview).toMatchObject({
              signer: "owner",
              enableVerificationGasFloor: null,
              enforcement: { calls: "none", expiry: "client", operationCount: "none" },
            });
            expect(ownerReview.reasons).toContain("owner_auto_single_operation");
            expect(ownerOperationPrompts).toBe(0);
            const rootOperation = await grant.sendCalls(calls);
            expect(sends).toBe(1);
            expect(ownerOperationPrompts).toBe(1);
            grant = await reopenGrant();
            const rootRecovered = await grant.getOperation({
              chain: CHAIN_ID,
              id: rootOperation.id,
            });
            if (!rootRecovered) throw new Error("root operation missing after reload");
            await harness.client.request({
              method: "anvil_mine" as never,
              params: ["0x3"] as never,
            });
            expect((await rootRecovered.wait()).status).toBe("finalized");
            expect(sends).toBe(1);
            expect(ownerOperationPrompts).toBe(1);
            // Root execution never created session installation evidence. The
            // next send must still use enable and leave the policy count at one.
            const review = await grant.reviewCalls(sendCallsInput());
            const durable = (await stores().grants.get(review.grantId)) as {
              value: { materializations: unknown[] };
            };
            expect(durable.value.materializations).toHaveLength(0);
          }
          const reviewed = await grant.reviewCalls(sendCallsInput()).then(
            () => true,
            () => false,
          );
          expect(usageError).toBeNull();
          expect(reviewed).toBe(true);
          const first = await grant
            .sendCalls(sendCallsInput())
            .catch((error: { code?: string; source?: string }) => {
              throw new Error(
                `first operation failed: ${error.code ?? "unknown"}/${error.source ?? "unknown"}`,
              );
            });
          expect(sends).toBe(1 + ownerOffset);
          // Close every SDK/store/port instance before advancing chain finality.
          const exactId = first.id;
          grant = await reopenGrant();
          const recovered = await grant.getOperation({ chain: CHAIN_ID, id: exactId });
          if (recovered === null) throw new Error("operation was not restored");
          expect(recovered.id).toBe(exactId);
          expect(await grant.account(CHAIN_ID)).toBe(address);
          expect(sends).toBe(1 + ownerOffset);
          // Recover after the containing block is well outside one request budget.
          await harness.client.request({
            method: "anvil_mine" as never,
            params: ["0x400", "0x0"] as never,
          });
          const beforeRecoveryReads = rpcRequests;
          const recoveryOutcome = await recovered.wait();
          expect({
            status: recoveryOutcome.status,
            state: recoveryOutcome.state,
            reason: "reason" in recoveryOutcome ? recoveryOutcome.reason : null,
          }).toMatchObject({ status: "finalized" });
          expect(rpcRequests - beforeRecoveryReads).toBeLessThan(24);
          expect(sends).toBe(1 + ownerOffset);
          const reference = references.get(exactId);
          if (!reference) throw new Error("fixture did not retain operation reference");
          const referencePort = chainPorts()[0];
          if (!referencePort) throw new Error("fixture did not configure observation");
          const referenceObserver = createUserOperationObserver(referencePort.observation);
          try {
            const result = await referenceObserver.observeReference({
              reference,
              observedAt: clock.now(),
              timeoutMs: 10_000,
            });
            expect(result.status).toBe("finalized");
            if (result.status === "finalized")
              expect(result.receipt.transactionHash).toBe(recoveryOutcome.transactionHash);
            expect(
              await referenceObserver.observeReference({
                reference: { ...reference, nonce: String(BigInt(reference.nonce) + 1n) },
                observedAt: clock.now(),
                timeoutMs: 10_000,
              }),
            ).toMatchObject({ status: "unreadable", reason: "receipt_invalid", receipt: null });
            expect(sends).toBe(1 + ownerOffset);
            expect(estimates).toBe(1 + ownerOffset);
            expect(ownerOperationPrompts).toBe(ownerOffset);
          } finally {
            await referenceObserver.close();
          }
          const second = await grant.sendCalls(sendCallsInput());
          expect((await second.wait()).status).toBe("finalized");
          if (!usageRequest) throw new Error("missing usage request");
          const observed = await ports.usage!(usageRequest);
          expect(observed).toMatchObject({ status: "complete", finalizedOperationCount: "2" });
          expect(sends).toBe(2 + ownerOffset);
          expect(modeBytes).toEqual([
            ...(ownerOffset ? [0n] : []),
            version === "0.3.3" ? 1n : 12n,
            0n,
          ]);
          expect(estimates).toBe(2 + ownerOffset);
          expect(approvalPrompts).toBe(mode === "local" ? 1 : 0);
          expect(ownerOperationPrompts).toBe(ownerOffset);
          if (version === "0.3.3") {
            await grant.revoke();
            expect(sends).toBe(3 + ownerOffset);
            expect(grant.state).toBe("revoking");
            grant = await reopenGrant();
            expect(grant.state).toBe("revoking");
            await grant.revoke();
            expect(sends).toBe(3 + ownerOffset);
            await harness.client.request({
              method: "anvil_mine" as never,
              params: ["0x3"] as never,
            });
            await grant.revoke();
            expect(grant.state).toBe("revoked");
            await grant.revoke();
            expect(sends).toBe(3 + ownerOffset);
            await expect(grant.sendCalls(sendCallsInput())).rejects.toMatchObject({
              code: "oaath_client_grant_inactive",
            });
            // A distinct permission never used for an application operation must
            // still consume its enable approval before revocation completes.
            let unused = await (await realm.oaath.connect()).requestPermission(
              permissionInput({ perChainOperationLimit: 3 }),
            );
            await unused.revoke();
            expect(unused.state).toBe("revoking");
            expect(sends).toBe(4 + ownerOffset);
            unused = await reopenGrant();
            await unused.revoke();
            expect(sends).toBe(4 + ownerOffset);
            await harness.client.request({
              method: "anvil_mine" as never,
              params: ["0x3"] as never,
            });
            await unused.revoke();
            expect(unused.state).toBe("revoked");
            expect(sends).toBe(4 + ownerOffset);
            expect(approvalPrompts).toBe(mode === "local" ? 2 : 0);
            expect(ownerOperationPrompts).toBe(mode === "local" ? 3 : 0);
          }
          expect(
            methods.every((method) =>
              [
                "eth_chainId",
                "eth_supportedEntryPoints",
                "eth_estimateUserOperationGas",
                "eth_sendUserOperation",
                "eth_getUserOperationReceipt",
              ].includes(method),
            ),
          ).toBe(true);
        } finally {
          await realm?.oaath.close();
          database.close();
          await new Promise<void>((resolve) => server.close(() => resolve()));
          local.stop();
        }
      },
      60_000,
    );
  },
);
