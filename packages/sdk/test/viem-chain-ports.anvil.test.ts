import { createServer } from "node:http";
import { OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION } from "@oaath/protocol";
import { IDBFactory } from "fake-indexeddb";
import { decodeEventLog, encodeFunctionData, parseEther, toHex } from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import type { OaathUsageRequest } from "../src/advanced.js";
import { grantProviderPort } from "../src/client/grant-handle.js";
import { KERNEL_V4_ENTRY_POINT_V07 } from "../src/kernel.js";
import {
  createIndexedDbCleanupStore,
  createIndexedDbContextStore,
  createIndexedDbGrantStoreAdapter,
  createIndexedDbKeyStore,
  createIndexedDbOperationStoreAdapter,
  createIndexedDbPreparedCallStoreAdapter,
  createIndexedDbWalletCallBundleStoreAdapter,
  openOaathDatabase,
} from "../src/persistence.js";
import { createViemChainPorts } from "../src/viem.js";
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
    it.each(["0.4.0", "0.3.3"] as const)(
      "Kernel %s Grant recovers a lost enable reply after reload and executes the installed session",
      async (version) => {
        const local = await startAnvil(CHAIN_ID, "prague", 1);
        const harness = await createHarness(local);
        let realm: ReturnType<typeof createRealm> | undefined;
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
              result = [KERNEL_V4_ENTRY_POINT_V07];
            else if (rpc.method === "eth_getUserOperationReceipt")
              result = receipts.get(String(rpc.params[0])) ?? null;
            else if (rpc.method === "eth_estimateUserOperationGas") {
              estimates += 1;
              const op = rpc.params[0] as Record<string, string>;
              expect(typeof op.signature === "string" && op.signature.length > 132).toBe(true);
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
              } as UserOperation<"0.7">;
              const hash = getUserOperationHash({
                userOperation: operation,
                entryPointAddress: KERNEL_V4_ENTRY_POINT_V07,
                entryPointVersion: "0.7",
                chainId: CHAIN_ID,
              });
              const transactionHash = await harness.wallet.sendTransaction({
                account: harness.submitter,
                chain: null,
                to: KERNEL_V4_ENTRY_POINT_V07,
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
                entryPoint: KERNEL_V4_ENTRY_POINT_V07,
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
              if (sends === 1) {
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
              ? await deployKernelV33Account(harness, CHAIN_ID, ownerCredential.address)
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
          const chainPorts = () =>
            createViemChainPorts(
              { [CHAIN_ID]: { publicRpcUrls: [`${url}/unavailable`, local.url], bundlerUrl: url } },
              { retry: { attempts: 2, delayMs: 0 }, maxRequests: 300 },
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
          function newRealm(relay?: ReturnType<typeof createRealm>["relay"]) {
            return createRealm({
              binding,
              stores: stores(),
              ...(relay ? { relay } : {}),
              validator,
              clock: createClock(Math.floor(Date.now() / 1000)),
              chain: {
                capability: {
                  ...ports!,
                  usage: async (request) => {
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
          realm = newRealm();
          let grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
          const address = await grant.account(CHAIN_ID);
          if (existing !== null) expect(address).toBe(existing.address.toLowerCase());
          if (version === "0.3.3") {
            const provider = grantProviderPort(grant);
            expect(await provider.probeValidityTimeRangeSupport(CHAIN_ID)).toEqual({
              status: "unsupported",
            });
            await expect(grant.revoke()).rejects.toMatchObject({
              source: "kernel_v33_revocation_unsupported",
            });
            expect(grant.state).toBe("active");
            expect(sends).toBe(0);
          }
          await harness.fund(await grant.account(CHAIN_ID), parseEther("1"));
          await harness.client.request({ method: "anvil_mine" as never, params: ["0x3"] as never });
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
          expect(sends).toBe(1);
          // Close every SDK/store/port instance before advancing chain finality.
          const exactId = first.id;
          const relay = realm.relay;
          await realm.oaath.close();
          database.close();
          database = await openOaathDatabase({ factory });
          ports = chainPorts()[0];
          if (!ports) throw new Error("chain missing");
          realm = newRealm(relay);
          const restored = await (await realm.oaath.connect()).resume();
          if (restored === null) throw new Error("Grant was not restored");
          grant = restored;
          const recovered = await grant.getOperation({ chain: CHAIN_ID, id: exactId });
          if (recovered === null) throw new Error("operation was not restored");
          expect(recovered.id).toBe(exactId);
          expect(await grant.account(CHAIN_ID)).toBe(address);
          expect(sends).toBe(1);
          await harness.client.request({ method: "anvil_mine" as never, params: ["0x3"] as never });
          expect((await recovered.wait()).status).toBe("finalized");
          expect(sends).toBe(1);
          const second = await grant.sendCalls(sendCallsInput());
          expect((await second.wait()).status).toBe("finalized");
          if (!usageRequest) throw new Error("missing usage request");
          const observed = await ports.usage!(usageRequest);
          expect(observed).toMatchObject({ status: "complete", finalizedOperationCount: "2" });
          expect(sends).toBe(2);
          expect(modeBytes).toEqual([version === "0.3.3" ? 1n : 12n, 0n]);
          expect(estimates).toBe(2);
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
