/** Existing Kernel account fixture over the public owner client and viem ports. */
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { p256 } from "@noble/curves/nist.js";
import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import {
  createOAAth,
  type OaathApprovalWallet,
  type OaathChainDescriptor,
  type OaathConnectedEoaPayer,
  type OaathOwnerClient,
} from "@oaath/sdk";
import { type KeyProfile, kernelDeployment, kernelKey } from "@oaath/sdk/kernel";
import { createViemChainPorts } from "@oaath/sdk/viem";
import {
  bytesToHex,
  createWalletClient,
  custom,
  encodeErrorResult,
  encodeFunctionData,
  type Hex,
  hexToBytes,
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
  /** The account's raw P-256 root owner key when `owner: "p256"`, counted in `signatureCount`. */
  readonly ownerKey: Readonly<KeyProfile> | null;
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
  /**
   * Plain `createOAAth` chain descriptors: the Anvil RPC plus this fixture's
   * bundler served over loopback HTTP, so the SDK builds its default ports.
   */
  readonly chainDescriptors: () => Promise<Readonly<Record<number, OaathChainDescriptor>>>;
  readonly mine: () => Promise<void>;
  readonly close: () => Promise<void>;
}

export async function createLocalOwnerAnvilFixture(
  input: {
    chainId?: number;
    wallet?: "browser" | "local";
    /** The existing account's Kernel version; the SDK under test must detect it. */
    kernelVersion?: "0.3.3" | "0.4.0";
    /** The account's root owner; `"p256"` requires Kernel `"0.4.0"`. Defaults to the ECDSA wallet. */
    owner?: "ecdsa" | "p256";
    bundler?: "accept" | "reject" | "uncertain";
    /** Fault injection for session estimation; owner execution remains real EntryPoint execution. */
    sessionValidation?: "rejected" | "unavailable";
  } = {},
): Promise<Readonly<LocalOwnerAnvilFixture>> {
  const chainId = input.chainId ?? 143;
  if (!Number.isSafeInteger(chainId) || chainId < 1) throw new Error("local_fixture_chain_invalid");
  const directory = await mkdtemp(join(tmpdir(), "oaath-owner-fixture-"));
  const p256Owner = input.owner === "p256";
  if (p256Owner && input.kernelVersion !== "0.4.0") throw new Error("local_fixture_owner_invalid");
  // The pinned P-256 validator needs the precompile Osaka carries.
  const chain = await startAnvil(chainId, p256Owner ? "osaka" : "prague");
  let signatures = 0;
  let client: Readonly<OaathOwnerClient> | undefined;
  let bundlerServer: Promise<{ server: Server; url: string }> | undefined;
  let closed = false;
  async function close() {
    const results = await Promise.allSettled([
      client?.close(),
      Promise.resolve().then(() => chain.stop()),
      bundlerServer?.then(
        ({ server }) => new Promise<void>((resolve) => server.close(() => resolve())),
      ),
    ]);
    await rm(directory, { recursive: true, force: true });
    closed = true;
    if (results.some((r) => r.status === "rejected"))
      throw new Error("local_fixture_cleanup_failed");
  }
  try {
    const stack = await deployKernelStack(chain, { p256: p256Owner });
    const deployment = kernelDeployment({ chainId });
    const deployment33 = kernelDeployment({ chainId, kernelVersion: "0.3.3" });
    const owner = privateKeyToAccount(generatePrivateKey());
    const p256Secret = p256.utils.randomPrivateKey();
    // A raw P-256 root owner: only compact low-s (r || s) crosses the boundary.
    const ownerKey = p256Owner
      ? kernelKey({
          credential: {
            version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
            kind: "p256",
            publicKey: bytesToHex(p256.getPublicKey(p256Secret, false)),
          },
          sign: async ({ hash }) => {
            signatures++;
            return `0x${p256.sign(hexToBytes(hash), p256Secret, { lowS: true, prehash: false }).toCompactHex()}`;
          },
        })
      : null;
    const address =
      input.kernelVersion === "0.4.0"
        ? await deployLocalV4OwnerAccount(
            chain,
            stack,
            ownerKey ?? kernelKey({ account: owner, validator: deployment33.ecdsaValidator }),
          )
        : await deployLocalV33Account(chain, stack, owner.address);
    await stack.fund(address, parseEther("10"));
    await stack.fund(owner.address, parseEther("10"));
    let bundlerSends = 0,
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
    // Loopback HTTP in front of the fixture bundler; no external host is reachable.
    const hostedBundler = () =>
      (bundlerServer ??= new Promise((resolve, reject) => {
        const server = createServer(async (request, response) => {
          const chunks: Buffer[] = [];
          for await (const chunk of request) chunks.push(chunk as Buffer);
          try {
            const answer = await rpcFetch(
              new Request("http://owner-bundler.test/", {
                method: request.method ?? "GET",
                headers: { "content-type": "application/json" },
                body: Buffer.concat(chunks).toString("utf8"),
              }),
            );
            response.writeHead(answer.status, { "content-type": "application/json" });
            response.end(await answer.text());
          } catch {
            response.writeHead(500).end();
          }
        });
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
          const endpoint = server.address();
          if (!endpoint || typeof endpoint === "string") return reject(new Error("no port"));
          resolve({ server, url: `http://127.0.0.1:${endpoint.port}` });
        });
      }));
    return Object.freeze({
      chainId,
      rpcUrl: chain.url,
      address,
      wallet,
      ownerKey,
      createChainPorts: ports,
      async chainDescriptors() {
        if (closed) throw new Error("local_fixture_closed");
        const { url } = await hostedBundler();
        return Object.freeze({ [chainId]: { publicRpcUrls: [chain.url], bundlerUrl: url } });
      },
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
            kind: "memory",
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
