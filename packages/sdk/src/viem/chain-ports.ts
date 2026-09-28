import {
  BaseError,
  createPublicClient,
  custom,
  decodeAbiParameters,
  encodeFunctionData,
  pad,
  parseAbi,
  toHex,
} from "viem";
import { entryPoint07Abi } from "viem/account-abstraction";
import type {
  OaathChainCapability,
  OaathQuoteRequest,
  OaathRegisteredPaymasterService,
  OaathUsageRequest,
} from "../client/grant-handle.js";
import {
  createKernelV33Reads,
  type KernelV33ReadRequest,
  type KernelV33Reads,
} from "../kernel/deployment/v33.js";
import { captureKernelGasPolicy, type KernelGasPolicy } from "../kernel/gas-policy.js";
import { resolvePolicyModule } from "../kernel/modules.js";
import {
  createKernelV4Reads,
  encodeKernelV4InstallNonceRead,
  encodeKernelV4NonceKey,
  type KernelV4AccountReadRequest,
  type KernelV4ReadClient,
} from "../kernel-v4.js";
import type { OperationObserverReadRequest } from "../operation-observer.js";
import {
  type PreparedUserOperation,
  parsePreparedUserOperation,
  type UnsignedUserOperationV07,
} from "../prepared-user-operation.js";
import type { Erc7677EstimationUserOperationV07 } from "../provider/erc7677.js";
import {
  evidence,
  integer,
  invalid,
  OaathRpcError,
  object,
  quantity,
  type RpcRequest,
  record,
  rpcOwner,
  url,
  urls,
  type ViemChainPortOptions,
} from "./rpc.js";

export interface ViemChainPortConfiguration {
  readonly publicRpcUrls: readonly string[];
  readonly bundlerUrl: string;
  readonly paymasterUrl?: string;
  readonly gas?: Readonly<KernelGasPolicy>;
}

export interface ViemChainCapability extends OaathChainCapability {
  readonly reads: OaathChainCapability["reads"] & KernelV33Reads;
}

const PUBLIC_METHODS = [
  "eth_chainId",
  "eth_getCode",
  "eth_getStorageAt",
  "eth_call",
  "eth_gasPrice",
  "eth_maxPriorityFeePerGas",
  "eth_feeHistory",
  "eth_getBlockByNumber",
  "eth_getBlockByHash",
  "eth_getTransactionByHash",
  "eth_getTransactionReceipt",
];
// eth_chainId and eth_supportedEntryPoints are ERC-4337 discovery methods.
const BUNDLER_METHODS = [
  "eth_chainId",
  "eth_supportedEntryPoints",
  "eth_estimateUserOperationGas",
  "eth_sendUserOperation",
  "eth_getUserOperationReceipt",
];
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const RATE_ABI = parseAbi([
  "function status(bytes32 id, address account) view returns (uint8)",
  "function rateLimitConfigs(bytes32 id, address account) view returns (uint48 interval, uint48 count, uint48 startAt)",
]);
const MODULE_ABI = parseAbi([
  "function isModuleInstalled(uint256 moduleType, address module, bytes context) view returns (bool)",
]);

function hex(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !/^0x(?:[0-9a-f]{2})*$/iu.test(value)) return evidence();
  return value.toLowerCase() as `0x${string}`;
}
function address(value: unknown): `0x${string}` {
  const result = hex(value);
  return result.length === 42 ? result : evidence();
}
function word(value: unknown): bigint {
  const data = hex(value);
  if (data.length !== 66) return evidence();
  return decodeAbiParameters([{ type: "uint256" }], data)[0];
}
function select(raw: unknown, fields: readonly string[]): unknown {
  if (raw === null) return null;
  const value = object(raw);
  return Object.fromEntries(
    fields.map((key) => [
      key,
      typeof value[key] === "string" ? (value[key] as string).toLowerCase() : value[key],
    ]),
  );
}
function block(raw: unknown): unknown {
  return select(raw, ["number", "hash", "parentHash", "transactions"]);
}
function gas(operation: Readonly<UnsignedUserOperationV07>) {
  return {
    callGasLimit: operation.callGasLimit,
    verificationGasLimit: operation.verificationGasLimit,
    preVerificationGas: operation.preVerificationGas,
    maxFeePerGas: operation.maxFeePerGas,
    maxPriorityFeePerGas: operation.maxPriorityFeePerGas,
  };
}
function wire(
  operation: Readonly<UnsignedUserOperationV07>,
  signature: `0x${string}`,
): Readonly<Erc7677EstimationUserOperationV07> {
  return {
    sender: operation.sender,
    nonce: toHex(BigInt(operation.nonce)),
    callData: operation.callData,
    callGasLimit: toHex(BigInt(operation.callGasLimit)),
    verificationGasLimit: toHex(BigInt(operation.verificationGasLimit)),
    preVerificationGas: toHex(BigInt(operation.preVerificationGas)),
    maxFeePerGas: toHex(BigInt(operation.maxFeePerGas)),
    maxPriorityFeePerGas: toHex(BigInt(operation.maxPriorityFeePerGas)),
    signature,
    ...(operation.factory === null
      ? {}
      : { factory: operation.factory.address, factoryData: operation.factory.data }),
    ...(operation.paymaster === null
      ? {}
      : {
          paymaster: operation.paymaster.address,
          paymasterData: operation.paymaster.data,
          paymasterVerificationGasLimit: toHex(BigInt(operation.paymaster.verificationGasLimit)),
          paymasterPostOpGasLimit: toHex(BigInt(operation.paymaster.postOpGasLimit)),
        }),
  };
}
function estimated(raw: unknown) {
  const result = object(raw);
  return {
    callGasLimit: quantity(result.callGasLimit).toString(),
    verificationGasLimit: quantity(result.verificationGasLimit).toString(),
    preVerificationGas: quantity(result.preVerificationGas).toString(),
    ...(result.paymasterVerificationGasLimit === undefined
      ? {}
      : {
          paymasterVerificationGasLimit: quantity(result.paymasterVerificationGasLimit).toString(),
        }),
    ...(result.paymasterPostOpGasLimit === undefined
      ? {}
      : { paymasterPostOpGasLimit: quantity(result.paymasterPostOpGasLimit).toString() }),
  };
}

function observer(publicRpc: RpcRequest, bundler: RpcRequest) {
  return Object.freeze({
    async read(request: OperationObserverReadRequest): Promise<unknown> {
      switch (request.type) {
        case "chain_id":
          return Number(quantity(await publicRpc("eth_chainId")));
        case "user_operation_receipt": {
          const raw = await bundler("eth_getUserOperationReceipt", [request.userOperationHash]);
          if (raw === null) return null;
          const value = object(raw);
          const receipt = object(value.receipt);
          return {
            userOperationHash: hex(value.userOpHash),
            entryPoint: address(value.entryPoint),
            sender: address(value.sender),
            nonce: toHex(quantity(value.nonce)),
            paymaster: value.paymaster === undefined ? ZERO_ADDRESS : address(value.paymaster),
            actualGasCost: toHex(quantity(value.actualGasCost)),
            actualGasUsed: toHex(quantity(value.actualGasUsed)),
            success: value.success,
            transactionHash: hex(receipt.transactionHash),
            blockNumber: toHex(quantity(receipt.blockNumber)),
            blockHash: hex(receipt.blockHash),
          };
        }
        case "transaction":
        case "transaction_execution":
          return select(
            await publicRpc("eth_getTransactionByHash", [request.transactionHash]),
            request.type === "transaction"
              ? ["hash", "to", "blockNumber", "blockHash", "transactionIndex"]
              : ["hash", "to", "blockNumber", "blockHash", "input"],
          );
        case "transaction_receipt": {
          const raw = await publicRpc("eth_getTransactionReceipt", [request.transactionHash]);
          if (raw === null) return null;
          const value = object(raw);
          if (!Array.isArray(value.logs)) return evidence();
          return {
            ...object(
              select(value, [
                "transactionHash",
                "blockNumber",
                "blockHash",
                "transactionIndex",
                "status",
                "gasUsed",
              ]),
            ),
            logs: value.logs.map((log) =>
              select(log, [
                "address",
                "blockNumber",
                "blockHash",
                "transactionHash",
                "transactionIndex",
                "logIndex",
                "removed",
                "topics",
                "data",
              ]),
            ),
          };
        }
        case "finalized_block":
          return block(await publicRpc("eth_getBlockByNumber", ["finalized", false]));
        case "canonical_block":
          return block(
            await publicRpc("eth_getBlockByNumber", [toHex(BigInt(request.blockNumber)), false]),
          );
        case "block_by_hash":
          return block(await publicRpc("eth_getBlockByHash", [request.blockHash, false]));
        case "replacement_candidate":
          return null; // No indexer: never claim to have found a replacement.
        case "entry_point_nonce":
          return publicRpc("eth_call", [
            {
              to: request.entryPoint,
              data: encodeFunctionData({
                abi: entryPoint07Abi,
                functionName: "getNonce",
                args: [request.account, BigInt(request.nonce) >> 64n],
              }),
            },
            toHex(BigInt(request.blockNumber)),
          ]);
        case "kernel_install_nonce":
          return publicRpc("eth_call", [
            {
              to: request.account,
              data: encodeKernelV4InstallNonceRead({
                key: (BigInt(request.nonce) >> 64n).toString(),
              }),
            },
            toHex(BigInt(request.blockNumber)),
          ]);
        case "kernel_permission_installed": {
          const answer = word(
            await publicRpc("eth_call", [
              {
                to: request.account,
                data: encodeFunctionData({
                  abi: MODULE_ABI,
                  functionName: "isModuleInstalled",
                  args: [6n, request.signer, request.permissionId],
                }),
              },
              toHex(BigInt(request.blockNumber)),
            ]),
          );
          return answer === 0n ? false : answer === 1n ? true : evidence();
        }
      }
    },
    async close() {},
  });
}

async function usage(publicRpc: RpcRequest, request: Readonly<OaathUsageRequest>) {
  const finalized = object(await publicRpc("eth_getBlockByNumber", ["finalized", false]));
  const blockHash = hex(finalized.hash);
  if (blockHash.length !== 66) return evidence();
  const blockNumber = quantity(finalized.number);
  // EIP-1898 binds all reads to this exact canonical finalized block, even on failover.
  const at = { blockHash, requireCanonical: true };
  const module = resolvePolicyModule("operation-limit");
  if (hex(await publicRpc("eth_getCode", [module, at])) === "0x") return evidence();
  const id = pad(hex(request.permissionId), { size: 32, dir: "right" });
  const account = address(request.account);
  const maximum = BigInt(request.maximumOperations);
  if (maximum < 1n || maximum >= 1n << 48n) return evidence();
  const status = word(
    await publicRpc("eth_call", [
      {
        to: module,
        data: encodeFunctionData({ abi: RATE_ABI, functionName: "status", args: [id, account] }),
      },
      at,
    ]),
  );
  let used = 0n;
  if (status === 1n) {
    const data = hex(
      await publicRpc("eth_call", [
        {
          to: module,
          data: encodeFunctionData({
            abi: RATE_ABI,
            functionName: "rateLimitConfigs",
            args: [id, account],
          }),
        },
        at,
      ]),
    );
    const [interval, remaining, startAt] = decodeAbiParameters(
      [{ type: "uint48" }, { type: "uint48" }, { type: "uint48" }],
      data,
    );
    if (interval !== 0 || startAt !== 0 || BigInt(remaining) > maximum) return evidence();
    used = maximum - BigInt(remaining);
  } else if (status !== 0n) return evidence();
  return Object.freeze({
    version: "oaath.grant-policy-usage/v1",
    status: "complete",
    grantId: request.grantId,
    chainId: request.chainId,
    finalizedOperationCount: used.toString(),
    through: {
      blockNumber: blockNumber.toString(),
      blockHash,
      observedAt: Math.floor(Date.now() / 1000),
    },
  });
}

/** Public reads and ERC-4337 transports from one configuration; constructing it makes no requests. */
export function createViemChainPorts(
  configuration: Readonly<Record<number, Readonly<ViemChainPortConfiguration>>>,
  options: ViemChainPortOptions = {},
): readonly Readonly<ViemChainCapability>[] {
  const entries = Object.entries(record(configuration));
  if (entries.length === 0 || entries.length > 64) return invalid();
  const owner = rpcOwner(options);
  return Object.freeze(
    entries.map(([key, value]) => {
      const chainId = integer(Number(key), 0, Number.MAX_SAFE_INTEGER);
      if (String(chainId) !== key) return invalid();
      const config = record(value, ["publicRpcUrls", "bundlerUrl", "paymasterUrl", "gas"]);
      const publicRpc = owner.pool(urls(config.publicRpcUrls), chainId, PUBLIC_METHODS);
      const bundler = owner.pool([url(config.bundlerUrl)], chainId, BUNDLER_METHODS);
      const paymasterUrl = config.paymasterUrl === undefined ? null : url(config.paymasterUrl);
      const paymaster =
        paymasterUrl === null
          ? null
          : owner.pool(
              [paymasterUrl],
              chainId,
              ["pm_getPaymasterStubData", "pm_getPaymasterData"],
              false,
            );
      const gasPolicy = captureKernelGasPolicy(chainId, config.gas);
      const client = createPublicClient({
        transport: custom(
          {
            request: ({ method, params }) =>
              publicRpc(method, params as readonly unknown[] | undefined),
          },
          { retryCount: 0 },
        ),
      });
      const readClient: KernelV4ReadClient = {
        getChainId: async () => Number(quantity(await publicRpc("eth_chainId"))),
        getCode: async ({ address }) => hex(await publicRpc("eth_getCode", [address, "latest"])),
        getStorageAt: async ({ address, slot }) =>
          hex(await publicRpc("eth_getStorageAt", [address, slot, "latest"])),
        call: async ({ to, data }) => ({
          data: hex(await publicRpc("eth_call", [{ to, data }, "latest"])),
        }),
      };
      const v4Reads = createKernelV4Reads(readClient);
      const v33Reads = createKernelV33Reads(readClient);
      const reads = Object.freeze({
        read(request: KernelV4AccountReadRequest | KernelV33ReadRequest): Promise<unknown> {
          switch (request.type) {
            case "kernel_account_version":
            case "kernel_account_entrypoint":
            case "kernel_account_root_validator":
            case "kernel_ecdsa_owner":
              return v33Reads.read(request);
            default:
              return v4Reads.read(request as KernelV4AccountReadRequest);
          }
        },
      });
      const observation = observer(publicRpc, bundler);

      async function estimate(
        prepared: Readonly<PreparedUserOperation>,
        userOperation: Readonly<Erc7677EstimationUserOperationV07>,
      ) {
        if (prepared.chainId !== chainId) return invalid();
        // An estimate may allocate provider resources; sponsorship invokes this stage once.
        return estimated(
          await bundler(
            "eth_estimateUserOperationGas",
            [userOperation, prepared.entryPoint.address],
            false,
          ),
        );
      }
      async function quote(request: Readonly<OaathQuoteRequest>) {
        const prepared = parsePreparedUserOperation(request.simulation.prepared);
        if (
          request.chainId !== chainId ||
          prepared.chainId !== chainId ||
          prepared.userOperation.sender !== request.account ||
          !["estimate", "sponsorship", "revalidate"].includes(request.purpose)
        )
          return invalid();
        const nonceKey = "0";
        const key = encodeKernelV4NonceKey({
          mode: request.mode,
          validation: request.validation,
          nonceKey,
        });
        if (BigInt(prepared.userOperation.nonce) !== BigInt(key) << 64n) return invalid();
        const nonce = word(
          await publicRpc("eth_call", [
            {
              to: prepared.entryPoint.address,
              data: encodeFunctionData({
                abi: entryPoint07Abi,
                functionName: "getNonce",
                args: [request.account, BigInt(key)],
              }),
            },
            "latest",
          ]),
        );
        if (nonce >> 64n !== BigInt(key)) return evidence();
        let quoted = gas(prepared.userOperation);
        if (request.purpose !== "revalidate") {
          const fees = await client.estimateFeesPerGas().catch((error: unknown) => {
            if (error instanceof BaseError) {
              const cause = error.walk((value) => value instanceof OaathRpcError);
              if (cause instanceof OaathRpcError) throw cause;
            }
            return evidence();
          });
          quoted = {
            ...quoted,
            maxFeePerGas: fees.maxFeePerGas.toString(),
            maxPriorityFeePerGas: fees.maxPriorityFeePerGas.toString(),
          };
        }
        if (request.purpose === "estimate") {
          const result = await estimate(
            prepared,
            wire(
              { ...prepared.userOperation, ...quoted, nonce: nonce.toString() },
              hex(request.simulation.signature),
            ),
          );
          quoted = {
            ...quoted,
            callGasLimit: result.callGasLimit,
            preVerificationGas: result.preVerificationGas,
            verificationGasLimit:
              BigInt(result.verificationGasLimit) > BigInt(quoted.verificationGasLimit)
                ? result.verificationGasLimit
                : quoted.verificationGasLimit,
          };
        }
        return Object.freeze({
          nonceKey,
          sequence: (nonce & ((1n << 64n) - 1n)).toString(),
          gas: Object.freeze(quoted),
        });
      }

      return Object.freeze({
        chainId,
        gas: gasPolicy,
        reads,
        observation,
        quote,
        bundler: Object.freeze({
          async probe(request: Parameters<OaathChainCapability["bundler"]["probe"]>[0]) {
            if (request.chainId !== chainId) return invalid();
            const supported = await bundler("eth_supportedEntryPoints");
            if (!Array.isArray(supported)) return evidence();
            return { accepting: true, chainId, supportedEntryPoints: supported.map(address) };
          },
        }),
        submission: Object.freeze({
          async open(request: Parameters<OaathChainCapability["submission"]["open"]>[0]) {
            const prepared = parsePreparedUserOperation(request.prepared);
            const signature = hex(request.signature);
            if (prepared.chainId !== chainId || request.route !== "bundler") return invalid();
            const operation = wire(prepared.userOperation, signature);
            let sent: Promise<unknown> | undefined;
            let closed = false;
            return Object.freeze({
              send() {
                if (closed) throw new OaathRpcError("oaath_rpc_unavailable");
                sent ??= bundler(
                  "eth_sendUserOperation",
                  [operation, prepared.entryPoint.address],
                  false,
                ).then((hash) => {
                  if (hex(hash) !== prepared.userOperationHash) return evidence();
                  return { userOperationHash: prepared.userOperationHash };
                });
                return sent;
              },
              async close() {
                closed = true;
              },
            });
          },
        }),
        usage: (request: Readonly<OaathUsageRequest>) => {
          if (request.chainId !== chainId) return invalid();
          return usage(publicRpc, request);
        },
        feePayer: null,
        paymasterService:
          paymaster === null || paymasterUrl === null
            ? null
            : Object.freeze({
                // Service identity excludes endpoint credentials; requests still
                // use the exact configured transport URL captured above.
                url: `${new URL(paymasterUrl).origin}${new URL(paymasterUrl).pathname}`.replace(
                  /\/$/u,
                  "",
                ),
                request: (request: Parameters<OaathRegisteredPaymasterService["request"]>[0]) =>
                  paymaster(request.method, request.params, false),
                estimate: (request: Parameters<OaathRegisteredPaymasterService["estimate"]>[0]) =>
                  estimate(parsePreparedUserOperation(request.prepared), request.userOperation),
              }),
        staticPaymasterConfigurationHash: null,
      } satisfies OaathChainCapability);
    }),
  );
}
