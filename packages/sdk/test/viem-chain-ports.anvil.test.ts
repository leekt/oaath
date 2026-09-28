import { createServer } from "node:http";
import { decodeEventLog, encodeFunctionData, parseEther, toHex } from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import type { OaathUsageRequest } from "../src/advanced.js";
import { KERNEL_V4_ENTRY_POINT_V07 } from "../src/kernel.js";
import { createViemChainPorts } from "../src/viem.js";
import { createHarness, deployKernelStack, startAnvil } from "./support/anvil.js";
import {
  CHAIN_ID,
  createClock,
  createRealm,
  permissionInput,
  sendCallsInput,
} from "./support/browser.js";

describe.skipIf(process.env.OAATH_REQUIRE_ANVIL !== "1")(
  "default ports against a real local chain",
  () => {
    it("recovers a lost first-enable reply, executes the installed session, and reads finalized policy usage", async () => {
      const local = await startAnvil(CHAIN_ID, "prague", 1);
      const harness = await createHarness(local);
      let realm: ReturnType<typeof createRealm> | undefined;
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
          else if (rpc.method === "eth_supportedEntryPoints") result = [KERNEL_V4_ENTRY_POINT_V07];
          else if (rpc.method === "eth_getUserOperationReceipt")
            result = receipts.get(String(rpc.params[0])) ?? null;
          else if (rpc.method === "eth_estimateUserOperationGas") {
            estimates += 1;
            const op = rpc.params[0] as Record<string, string>;
            expect(typeof op.signature === "string" && op.signature.length > 132).toBe(true);
            expect(op.factory !== undefined).toBe(sends === 0);
            result = {
              callGasLimit: "0xdbba0",
              verificationGasLimit: "0x2dc6c0",
              preVerificationGas: "0x249f0",
            };
          } else if (rpc.method === "eth_sendUserOperation") {
            sends += 1;
            const wire = rpc.params[0] as Record<string, string>;
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
            await harness.client.request({
              method: "anvil_mine" as never,
              params: ["0x3"] as never,
            });
            if (sends === 1) {
              // Acceptance happened, but the response is lost. Observation is
              // the only recovery; the transport must not send again.
              response.writeHead(502).end("lost reply");
              return;
            }
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
        await deployKernelStack(harness);
        for (const module of [
          harness.fixture.ecdsaSigner,
          harness.fixture.callPolicy,
          harness.fixture.validityPolicy,
          harness.fixture.rateLimitPolicy,
        ])
          await harness.deployModule(module);
        const validator = await harness.deployValidatorCreate2();
        await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
        const endpoint = server.address();
        if (!endpoint || typeof endpoint === "string") throw new Error("local RPC unavailable");
        const url = `http://127.0.0.1:${endpoint.port}`;
        const [ports] = createViemChainPorts(
          { [CHAIN_ID]: { publicRpcUrls: [`${url}/unavailable`, local.url], bundlerUrl: url } },
          { retry: { attempts: 2, delayMs: 0 }, maxRequests: 300 },
        );
        if (!ports) throw new Error("chain missing");
        realm = createRealm({
          validator,
          clock: createClock(Math.floor(Date.now() / 1000)),
          chain: {
            capability: {
              ...ports,
              usage: async (request) => {
                usageRequest = request;
                try {
                  return await ports.usage!(request);
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
        const grant = await (await realm.oaath.connect()).requestPermission(permissionInput());
        await harness.fund(await grant.account(CHAIN_ID), parseEther("1"));
        await harness.client.request({ method: "anvil_mine" as never, params: ["0x3"] as never });
        const reviewed = await grant.reviewCalls(sendCallsInput()).then(
          () => true,
          () => false,
        );
        expect(usageError).toBeNull();
        expect(reviewed).toBe(true);
        const first = await grant.sendCalls(sendCallsInput());
        expect((await first.wait()).status).toBe("finalized");
        const second = await grant.sendCalls(sendCallsInput());
        expect((await second.wait()).status).toBe("finalized");
        if (!usageRequest) throw new Error("missing usage request");
        const observed = await ports.usage!(usageRequest);
        expect(observed).toMatchObject({ status: "complete", finalizedOperationCount: "2" });
        expect(sends).toBe(2);
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
        await new Promise<void>((resolve) => server.close(() => resolve()));
        local.stop();
      }
    }, 60_000);
  },
);
