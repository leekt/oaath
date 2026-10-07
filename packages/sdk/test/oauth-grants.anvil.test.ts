/**
 * A dapp asks for a Grant with createOAAth({ approvals: { kind: "oauth" } })
 * and the account root approves it in the (in-memory) portal. On a local
 * chain, the Grant's first sendCalls deploys the counterfactual Kernel 0.4.0
 * account, installs the permission in enable mode and executes the covered
 * call. After a reload the Grant and its operation come back from IndexedDB and
 * observation finalizes it without submitting anything new.
 */
import { createServer } from "node:http";
import { IDBFactory } from "fake-indexeddb";
import { decodeEventLog, encodeFunctionData, parseEther, toHex } from "viem";
import {
  entryPoint07Abi,
  getUserOperationHash,
  toPackedUserOperation,
  type UserOperation,
} from "viem/account-abstraction";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { createCetaneChainPorts } from "../src/cetane.js";
import { createOAAth } from "../src/index.js";
import { ECDSA_VALIDATOR } from "../src/kernel/deployment/v33.js";
import { kernelDeployment, prepareKernelPermissionApproval } from "../src/kernel.js";
import { type AnvilChain, createHarness, deployKernelStack, startAnvil } from "./support/anvil.js";
import { installOAuthPortal, ORIGIN } from "./support/oauth-portal.js";
import { portalPermissionRequest, portalRoot } from "./support/portal-roots.js";

const requireAnvil = process.env.OAATH_REQUIRE_ANVIL === "1";
const CHAIN_ID = 8_453;
const TARGET = `0x${"7a".repeat(20)}` as const;

const chains: AnvilChain[] = [];
afterAll(() => {
  for (const chain of chains) chain.stop();
});
afterEach(() => vi.unstubAllGlobals());

(requireAnvil ? describe : describe.skip)("OAuth-approved Grants on a local chain", () => {
  it("first sendCalls deploys, enables and executes; reload observes without resubmitting", async () => {
    const local = await startAnvil(CHAIN_ID, "osaka", 1);
    chains.push(local);
    const harness = await createHarness(local);
    await deployKernelStack(harness);
    for (const module of [
      harness.fixture.ecdsaSigner,
      harness.fixture.callPolicy,
      harness.fixture.validityPolicy,
      harness.fixture.rateLimitPolicy,
    ])
      await harness.deployModule(module);
    const v33 = (await import("./fixtures/kernel-v33-deployments.json")).default;
    await harness.deployCreate2(v33.ecdsaValidator.deploymentInput as `0x${string}`);
    expect(await harness.client.getCode({ address: ECDSA_VALIDATOR })).toBeTruthy();

    // The portal account: factory-derived from one ECDSA root.
    const root = portalRoot("ecdsa");
    const now = Number((await harness.client.getBlock()).timestamp);
    const account = (
      await prepareKernelPermissionApproval({
        request: portalPermissionRequest({ root, target: TARGET, requestedAt: now }),
        chainId: CHAIN_ID,
        reads: harness.reads,
      })
    ).signingRequest.signer.account;
    await harness.fund(account, parseEther("1"));
    const portal = await installOAuthPortal({ chainId: CHAIN_ID, account, root });

    // Only the 4337 facade is a fixture; it hands each operation to the
    // EntryPoint on Anvil. Reads, receipts and finality come from Anvil.
    const deployment = kernelDeployment({ chainId: CHAIN_ID });
    const receipts = new Map<string, unknown>();
    const sent: UserOperation<"0.9">[] = [];
    const server = createServer(async (request, response) => {
      let body = "";
      for await (const chunk of request) body += String(chunk);
      const rpc = JSON.parse(body) as { id: number; method: string; params: unknown[] };
      let result: unknown;
      if (rpc.method === "eth_chainId") result = toHex(CHAIN_ID);
      else if (rpc.method === "eth_supportedEntryPoints") result = [deployment.entryPoint.address];
      else if (rpc.method === "eth_getUserOperationReceipt")
        result = receipts.get(String(rpc.params[0])) ?? null;
      else if (rpc.method === "eth_estimateUserOperationGas")
        result = {
          callGasLimit: "0xdbba0",
          verificationGasLimit: "0x2dc6c0",
          preVerificationGas: "0x249f0",
        };
      else if (rpc.method === "eth_sendUserOperation") {
        const wire = rpc.params[0] as Record<string, string>;
        const operation = {
          ...wire,
          nonce: BigInt(wire.nonce!),
          callGasLimit: BigInt(wire.callGasLimit!),
          verificationGasLimit: BigInt(wire.verificationGasLimit!),
          preVerificationGas: BigInt(wire.preVerificationGas!),
          maxFeePerGas: BigInt(wire.maxFeePerGas!),
          maxPriorityFeePerGas: BigInt(wire.maxPriorityFeePerGas!),
        } as UserOperation<"0.9">;
        sent.push(operation);
        const hash = getUserOperationHash({
          userOperation: operation,
          entryPointAddress: deployment.entryPoint.address,
          entryPointVersion: deployment.entryPoint.version,
          chainId: CHAIN_ID,
        });
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
        const receipt = await harness.client.waitForTransactionReceipt({ hash: transactionHash });
        const event = receipt.logs
          .map((log) => {
            try {
              return decodeEventLog({ abi: entryPoint07Abi, topics: log.topics, data: log.data });
            } catch {
              return null;
            }
          })
          .find((event) => event?.eventName === "UserOperationEvent");
        if (!event || event.eventName !== "UserOperationEvent")
          throw new Error("local operation event missing");
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
        await harness.client.request({ method: "anvil_mine" as never, params: ["0x3"] as never });
        result = hash;
      } else throw new Error("ordinary RPC reached bundler");
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const endpoint = server.address();
      if (!endpoint || typeof endpoint === "string") throw new Error("local RPC unavailable");
      const bundlerUrl = `http://127.0.0.1:${endpoint.port}`;
      const owned = new Set([bundlerUrl, local.url].map((value) => new URL(value).href));
      const factory = new IDBFactory();
      const open = () =>
        createOAAth({
          chains: createCetaneChainPorts(
            { [CHAIN_ID]: { publicRpcUrls: [local.url], bundlerUrl } },
            {
              maxRequests: 300,
              async fetch(request) {
                if (!owned.has(request.url)) throw new Error("only owned RPC endpoints");
                return fetch(request);
              },
            },
          ),
          approvals: portal.approvals,
          stores: { kind: "indexeddb", factory },
          origin: ORIGIN,
        });
      const calls = {
        chain: CHAIN_ID,
        calls: [{ target: TARGET, value: "500", data: "0x12345678" }],
      };

      let realm = open();
      const grant = await (await realm.connect()).requestPermission({
        chainScope: "all",
        permissions: [
          { calls: [{ target: TARGET, selectors: ["0x12345678"], valueLimit: "500" }] },
        ],
        expiresIn: 1_800,
        perChainOperationLimit: 3,
      });
      expect(grant.state).toBe("active");
      expect(await grant.account(CHAIN_ID)).toBe(account);
      expect(await harness.client.getCode({ address: account })).toBeFalsy();

      const first = await grant.sendCalls(calls);
      expect(sent).toHaveLength(1);
      // Enable mode on a counterfactual account: the factory deploys it.
      expect(BigInt(sent[0]!.nonce) >> 248n).toBe(12n);
      expect(sent[0]!.factory).toBeTruthy();
      expect(await harness.client.getCode({ address: account })).toBeTruthy();
      expect(await harness.client.getBalance({ address: TARGET })).toBe(500n);
      await realm.close();

      // Reload: a new realm over the same IndexedDB, no popup, no new send.
      realm = open();
      const resumed = await (await realm.connect()).resume();
      if (resumed === null) throw new Error("Grant was not restored");
      const recovered = await resumed.getOperation({ chain: CHAIN_ID, id: first.id });
      if (recovered === null) throw new Error("operation was not restored");
      await harness.client.request({ method: "anvil_mine" as never, params: ["0x40"] as never });
      expect((await recovered.wait()).status).toBe("finalized");
      expect(sent).toHaveLength(1);
      expect(portal.window.open).toHaveBeenCalledTimes(1);

      // The installed permission now validates without enable.
      expect((await (await resumed.sendCalls(calls)).wait()).status).toBe("finalized");
      expect(sent).toHaveLength(2);
      expect(BigInt(sent[1]!.nonce) >> 248n).toBe(0n);
      expect(await harness.client.getBalance({ address: TARGET })).toBe(1_000n);
      await realm.close();
    } finally {
      server.close();
    }
  }, 120_000);
});
