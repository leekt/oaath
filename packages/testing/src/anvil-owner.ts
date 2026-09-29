/** Existing Kernel account fixture over the public owner client and viem ports. */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createOAAth,
  type OaathApprovalWallet,
  type OaathConnectedEoaPayer,
  type OaathOwnerClient,
} from "@oaath/sdk";
import { kernelDeployment } from "@oaath/sdk/kernel";
import { createViemChainPorts } from "@oaath/sdk/viem";
import {
  createWalletClient,
  custom,
  encodeErrorResult,
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
import { readLocalOperationReceipt } from "./anvil-observation.mjs";
import { deployKernelStack, startAnvil } from "./anvil-process.mjs";
import { deployLocalV4OwnerAccount } from "./anvil-v4-owner.js";
import { deployLocalV33Account } from "./anvil-v33.js";
import { createSqliteOperationStoreAdapter } from "./sqlite-store.js";

type OwnerWallet = OaathApprovalWallet & OaathConnectedEoaPayer["wallet"];
export interface LocalOwnerAnvilFixture {
  readonly chainId: number;
  readonly rpcUrl: string;
  readonly address: Hex;
  readonly wallet: OwnerWallet;
  readonly signatureCount: number;
  readonly bundlerSubmissionCount: number;
  readonly fallbackSubmissionCount: number;
  readonly sessionEstimationCount: number;
  /** SDK HTTP requests across all port instances; setup transactions are excluded. */
  readonly rpcRequestCount: number;
  /** Existing local RPC handler for browser harnesses. The caller owns HTTP hosting and budgets. */
  readonly rpcFetch: (request: Request) => Promise<Response>;
  /** Reopens the SDK and SQLite journal; no prior operation handle survives. */
  readonly openClient: () => Promise<Readonly<OaathOwnerClient>>;
  /** Fresh bounded public SDK ports for testing local client composition. */
  readonly createChainPorts: () => ReturnType<typeof createViemChainPorts>;
  readonly mine: () => Promise<void>;
  readonly close: () => Promise<void>;
}

export async function createLocalOwnerAnvilFixture(
  input: {
    chainId?: number;
    wallet?: "browser" | "local";
    /** The existing account's Kernel version; the SDK under test must detect it. */
    kernelVersion?: "0.3.3" | "0.4.0";
    bundler?: "accept" | "reject" | "uncertain";
    /** Fault injection for session estimation; owner execution remains real EntryPoint execution. */
    sessionValidation?: "rejected" | "unavailable";
  } = {},
): Promise<Readonly<LocalOwnerAnvilFixture>> {
  const chainId = input.chainId ?? 143;
  if (!Number.isSafeInteger(chainId) || chainId < 1) throw new Error("local_fixture_chain_invalid");
  const directory = await mkdtemp(join(tmpdir(), "oaath-owner-fixture-"));
  const chain = await startAnvil(chainId);
  let client: Readonly<OaathOwnerClient> | undefined;
  let closed = false;
  async function close() {
    const results = await Promise.allSettled([
      client?.close(),
      Promise.resolve().then(() => chain.stop()),
    ]);
    await rm(directory, { recursive: true, force: true });
    closed = true;
    if (results.some((r) => r.status === "rejected"))
      throw new Error("local_fixture_cleanup_failed");
  }
  try {
    const stack = await deployKernelStack(chain);
    const deployment = kernelDeployment({ chainId });
    const owner = privateKeyToAccount(generatePrivateKey());
    const address =
      input.kernelVersion === "0.4.0"
        ? await deployLocalV4OwnerAccount(chain, stack, owner)
        : await deployLocalV33Account(chain, stack, owner.address);
    await stack.fund(address, parseEther("10"));
    await stack.fund(owner.address, parseEther("10"));
    let signatures = 0,
      bundlerSends = 0,
      fallbackSends = 0;
    let sessionEstimates = 0;
    let rpcRequests = 0;
    let rejected: UserOperation<"0.7"> | undefined;
    const localWallet = createWalletClient({
      account: owner,
      transport: http(chain.url, { retryCount: 0 }),
    });
    const mine = async () => {
      await chain.rpc("anvil_mine", ["0x3"]);
    };
    async function fallback(data: Hex, to: Hex) {
      if (!rejected || to.toLowerCase() !== deployment.entryPoint.address)
        throw new Error("local_fixture_unreviewed_fallback");
      const expected = encodeFunctionData({
        abi: entryPoint07Abi,
        functionName: "handleOps",
        args: [[toPackedUserOperation(rejected)], owner.address],
      });
      if (data !== expected) throw new Error("local_fixture_changed_operation");
      fallbackSends++;
      const hash = await localWallet.sendTransaction({ chain: null, to, data, gas: 8_000_000n });
      await chain.client.waitForTransactionReceipt({ hash });
      await mine();
      return hash;
    }
    const wallet: OwnerWallet =
      input.wallet === "browser"
        ? createWalletClient({
            account: owner.address,
            transport: custom({
              request: async ({ method, params }) => {
                if (method === "eth_chainId") return toHex(chainId);
                if (method === "eth_accounts") return [owner.address];
                if (method === "personal_sign") {
                  const [digest, signer] = params as [Hex, string];
                  if (signer.toLowerCase() !== owner.address.toLowerCase())
                    throw new Error("local_fixture_owner_changed");
                  signatures++;
                  return owner.signMessage({ message: { raw: digest } });
                }
                if (method === "eth_signTypedData_v4") {
                  const [signer, encoded] = params as [string, string];
                  if (signer.toLowerCase() !== owner.address.toLowerCase())
                    throw new Error("local_fixture_owner_changed");
                  signatures++;
                  return owner.signTypedData(JSON.parse(encoded));
                }
                if (method === "eth_sendTransaction") {
                  const [tx] = params as [
                    { from: Hex; to: Hex; data: Hex; value: Hex; chainId: Hex },
                  ];
                  if (
                    tx.from !== owner.address.toLowerCase() ||
                    tx.chainId !== toHex(chainId) ||
                    tx.value !== "0x0"
                  )
                    throw new Error("local_fixture_transaction_changed");
                  return fallback(tx.data, tx.to);
                }
                throw new Error("local_fixture_wallet_method_invalid");
              },
            }),
          })
        : {
            ...localWallet,
            async signMessage(request: Parameters<typeof localWallet.signMessage>[0]) {
              signatures++;
              return localWallet.signMessage(request);
            },
            async signTypedData(request: Parameters<OaathApprovalWallet["signTypedData"]>[0]) {
              signatures++;
              return localWallet.signTypedData(request);
            },
            async sendTransaction(request: Parameters<typeof localWallet.sendTransaction>[0]) {
              if (!request.to || !request.data || request.value !== 0n)
                throw new Error("local_fixture_transaction_invalid");
              return fallback(request.data, request.to);
            },
          };
    const rpcFetch = async (request: Request): Promise<Response> => {
      if (closed) throw new Error("local_fixture_closed");
      if (request.method !== "POST") throw new Error("local_fixture_request_invalid");
      rpcRequests++;
      if (new URL(request.url).origin === chain.url) return fetch(request);
      if (new URL(request.url).origin !== "http://owner-bundler.test")
        throw new Error("local_fixture_endpoint_invalid");
      const { id, method, params } = await request.json();
      let result: unknown;
      if (method === "eth_chainId") result = toHex(chainId);
      else if (method === "eth_supportedEntryPoints") result = [deployment.entryPoint.address];
      // Fixed local estimate; real EntryPoint validation and execution prove fit.
      else if (method === "eth_estimateUserOperationGas") {
        // Kernel's permission validation type is the byte below the mode byte.
        if (((BigInt(params[0].nonce) >> 240n) & 0xffn) === 2n) {
          sessionEstimates++;
          if (input.sessionValidation === "unavailable") return new Response(null, { status: 503 });
          if (input.sessionValidation === "rejected")
            return Response.json({
              jsonrpc: "2.0",
              id,
              error: {
                code: -32500,
                message: "fixture account validation rejection",
                data: encodeErrorResult({
                  abi: entryPoint07Abi,
                  errorName: "FailedOpWithRevert",
                  args: [0n, "AA23 reverted", "0x"],
                }),
              },
            });
        }
        result = {
          callGasLimit: toHex(5_000_000),
          // Cold installation includes call, time, and operation-limit policies.
          // The fixture must fit this on ordinary EVM chains, without
          // relying on a chain-specific gas multiplier.
          verificationGasLimit: toHex(1_000_000),
          preVerificationGas: toHex(100_000),
        };
      } else if (method === "eth_getUserOperationReceipt") {
        const receipt = await readLocalOperationReceipt(chain, params[0]);
        result =
          receipt === null
            ? null
            : {
                userOpHash: receipt.userOperationHash,
                entryPoint: receipt.entryPoint,
                sender: receipt.sender,
                nonce: receipt.nonce,
                actualGasCost: receipt.actualGasCost,
                actualGasUsed: receipt.actualGasUsed,
                success: receipt.success,
                receipt: {
                  transactionHash: receipt.transactionHash,
                  blockHash: receipt.blockHash,
                  blockNumber: receipt.blockNumber,
                },
              };
      } else if (method === "eth_sendUserOperation") {
        bundlerSends++;
        const wire = params[0];
        const operation = {
          ...wire,
          ...Object.fromEntries(
            [
              "nonce",
              "callGasLimit",
              "verificationGasLimit",
              "preVerificationGas",
              "maxFeePerGas",
              "maxPriorityFeePerGas",
            ].map((key) => [key, BigInt(wire[key])]),
          ),
        } as UserOperation<"0.7">;
        if (input.bundler === "uncertain") return new Response(null, { status: 503 });
        if (input.bundler === "reject") {
          rejected = operation;
          return Response.json({
            jsonrpc: "2.0",
            id,
            error: { code: -32500, message: "local refusal" },
          });
        }
        const hash = await stack.wallet.sendTransaction({
          account: stack.submitter,
          chain: null,
          to: deployment.entryPoint.address,
          gas: 8_000_000n,
          data: encodeFunctionData({
            abi: entryPoint07Abi,
            functionName: "handleOps",
            args: [[toPackedUserOperation(operation)], stack.submitter.address],
          }),
        });
        if ((await chain.client.waitForTransactionReceipt({ hash })).status !== "success")
          throw new Error("local_fixture_operation_reverted");
        await mine();
        result = getUserOperationHash({
          userOperation: operation,
          entryPointAddress: deployment.entryPoint.address,
          entryPointVersion: "0.7",
          chainId,
        });
      } else throw new Error("local_fixture_bundler_method_invalid");
      return Response.json({ jsonrpc: "2.0", id, result });
    };
    const ports = () =>
      createViemChainPorts(
        { [chainId]: { publicRpcUrls: [chain.url], bundlerUrl: "http://owner-bundler.test" } },
        { maxRequests: 1_000, fetch: rpcFetch },
      );
    return Object.freeze({
      chainId,
      rpcUrl: chain.url,
      address,
      wallet,
      createChainPorts: ports,
      rpcFetch,
      get signatureCount() {
        return signatures;
      },
      get bundlerSubmissionCount() {
        return bundlerSends;
      },
      get fallbackSubmissionCount() {
        return fallbackSends;
      },
      get sessionEstimationCount() {
        return sessionEstimates;
      },
      get rpcRequestCount() {
        return rpcRequests;
      },
      async openClient() {
        if (closed) throw new Error("local_fixture_closed");
        await client?.close();
        client = createOAAth({
          chains: ports(),
          stores: {
            operations: createSqliteOperationStoreAdapter(join(directory, "operations.db")),
          },
        });
        return client;
      },
      mine,
      close,
    });
  } catch {
    await close();
    throw new Error("local_owner_fixture_failed");
  }
}
