import { entryPointAbi } from "@oaath/protocol";
import { createPublicClient, custom } from "cetane";
import {
  decodeAbiParameters,
  decodeEventLog,
  encodeFunctionData,
  keccak256,
  padHex,
  parseAbi,
  toHex,
} from "cetane/utils";
import type {
  OaathChainCapability,
  OaathChainSponsorship,
  OaathQuoteRequest,
  OaathUsageRequest,
} from "../client/grant-handle.js";
import {
  createKernelReads,
  type KernelReadClient,
  type KernelReads,
} from "../kernel/deployment/account.js";
import { encodeKernelV33NonceKey } from "../kernel/deployment/v33-operation.js";
import { captureKernelGasPolicy, type KernelGasPolicy } from "../kernel/gas-policy.js";
import { resolvePolicyModule } from "../kernel/modules.js";
import { readKernelV33PermissionState } from "../kernel/permission/v33-revocation.js";
import { encodeKernelV4InstallNonceRead, encodeKernelV4NonceKey } from "../kernel-v4.js";
import type { OperationObserverReadRequest } from "../operation-observer.js";
import {
  type PreparedUserOperation,
  parsePreparedUserOperation,
  type UnsignedUserOperationV07,
} from "../prepared-user-operation.js";
import type { Erc7677EstimationUserOperationV07 } from "../provider/erc7677.js";
import type { OaathBundlerProbeRequest } from "../routing/erc4337/bundler.js";
import {
  type CetaneChainPortOptions,
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
} from "./rpc.js";

export interface CetaneChainPortConfiguration {
  readonly publicRpcUrls: readonly string[];
  /** Read endpoint headers only; never sent to bundler/paymaster URLs. Captured at construction. */
  readonly headers?: Readonly<Record<string, string>>;
  /** Omit for public-chain reads and direct-receipt observation without a submission route. */
  readonly bundlerUrl?: string;
  /**
   * Bundler endpoint headers only (for example `x-api-key`); never sent to read
   * or paymaster URLs. Captured at construction; values never appear in errors.
   */
  readonly bundlerHeaders?: Readonly<Record<string, string>>;
  readonly paymasterUrl?: string;
  /**
   * The bundler pays chain gas itself (a relay such as bundle_rs in fast mode):
   * every quoted operation carries `maxFeePerGas = 0` and
   * `maxPriorityFeePerGas = 0`, so the account needs no funds and no paymaster.
   * Gas limits still come from the bundler's `eth_estimateUserOperationGas`.
   * Requires `bundlerUrl`; refused together with `paymasterUrl`.
   */
  readonly relayPaysGas?: boolean;
  readonly gas?: Readonly<KernelGasPolicy>;
}

export interface CetaneChainCapability extends OaathChainCapability {
  readonly reads: KernelReads;
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
type Erc7677ChainSponsorship = Extract<OaathChainSponsorship, { kind: "erc7677" }>;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const eventAbi = entryPointAbi.find(
  (item) => item.type === "event" && item.name === "UserOperationEvent",
)!;
const USER_OPERATION_EVENT = keccak256(
  new TextEncoder().encode(
    `${eventAbi.name}(${eventAbi.inputs.map(({ type }) => type).join(",")})`,
  ),
);
const RATE_ABI = parseAbi([
  "function status(bytes32 id, address account) view returns (uint8)",
  "function rateLimitConfigs(bytes32 id, address account) view returns (uint48 interval, uint48 count, uint48 startAt)",
]);
const WINDOW_RATE_ABI = parseAbi([
  "function status(bytes32 id, address account) view returns (uint8)",
  "function rateLimitConfigs(bytes32 id, address account) view returns (uint48 interval, uint48 initialCount)",
  "function rateLimitState(bytes32 id, address account) view returns (uint48 storedCount, uint48 resetDate)",
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

/** A transaction hint locates an event; OperationObserver still verifies every inclusion fact. */
async function directReceipt(
  publicRpc: RpcRequest,
  request: Extract<OperationObserverReadRequest, { type: "user_operation_receipt" }>,
) {
  const hint = request.transaction;
  if (hint === undefined) return evidence();
  const raw = await publicRpc("eth_getTransactionReceipt", [hint.hash]);
  if (raw === null) return null;
  const receipt = object(raw);
  if (hex(receipt.transactionHash) !== hint.hash || !Array.isArray(receipt.logs)) return evidence();
  if (receipt.logs.length > 10_000) return evidence();
  if (quantity(receipt.status) === 0n) return null;
  if (quantity(receipt.status) !== 1n) return evidence();
  let result: unknown = null;
  for (const rawLog of receipt.logs) {
    const log = object(rawLog);
    if (address(log.address) !== hint.entryPoint || !Array.isArray(log.topics)) continue;
    if (
      typeof log.topics[0] !== "string" ||
      log.topics[0].toLowerCase() !== USER_OPERATION_EVENT ||
      typeof log.topics[1] !== "string" ||
      log.topics[1].toLowerCase() !== request.userOperationHash
    )
      continue;
    if (result !== null) return evidence();
    const event = (() => {
      try {
        return decodeEventLog({
          abi: entryPointAbi,
          topics: log.topics as [`0x${string}`, ...`0x${string}`[]],
          data: hex(log.data),
        });
      } catch {
        return evidence();
      }
    })();
    if (event.eventName !== "UserOperationEvent") return evidence();
    result = {
      userOperationHash: hex(event.args.userOpHash),
      entryPoint: hint.entryPoint,
      sender: address(event.args.sender),
      nonce: toHex(event.args.nonce),
      paymaster: address(event.args.paymaster),
      actualGasCost: toHex(event.args.actualGasCost),
      actualGasUsed: toHex(event.args.actualGasUsed),
      success: event.args.success,
      transactionHash: hint.hash,
      blockNumber: toHex(quantity(receipt.blockNumber)),
      blockHash: hex(receipt.blockHash),
    };
  }
  return result;
}

function observer(publicRpc: RpcRequest, bundler: RpcRequest) {
  return Object.freeze({
    async read(request: OperationObserverReadRequest): Promise<unknown> {
      switch (request.type) {
        case "chain_id":
          return Number(quantity(await publicRpc("eth_chainId")));
        case "user_operation_receipt": {
          if (request.transaction !== undefined) return directReceipt(publicRpc, request);
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
        case "replacement_candidate":
          return null; // No indexer: never claim to have found a replacement.
        case "entry_point_nonce":
          return publicRpc("eth_call", [
            {
              to: request.entryPoint,
              data: encodeFunctionData({
                abi: entryPointAbi,
                functionName: "getNonce",
                args: [request.account, BigInt(request.nonce) >> 64n],
              }),
            },
            toHex(BigInt(request.blockNumber)),
          ]);
        case "kernel_v33_permission_state":
          return readKernelV33PermissionState({
            permissionId: request.permissionId,
            call: (data) =>
              publicRpc("eth_call", [
                { to: request.account, data },
                toHex(BigInt(request.blockNumber)),
              ]),
          });
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
  const finalizedAt = quantity(finalized.timestamp);
  // EIP-1898 binds all reads to this exact canonical finalized block, even on failover.
  const at = { blockHash, requireCanonical: true };
  const windowed = request.intervalSeconds !== null;
  const module = resolvePolicyModule(windowed ? "rate-limit" : "operation-limit");
  if (hex(await publicRpc("eth_getCode", [module, at])) === "0x") return evidence();
  const id = padHex(hex(request.permissionId), { size: 32, dir: "right" });
  const account = address(request.account);
  const maximum = BigInt(request.maximumOperations);
  if (maximum < 1n || maximum >= 1n << 48n) return evidence();
  const interval = windowed ? BigInt(request.intervalSeconds) : 0n;
  if (windowed && (interval < 1n || interval >= 1n << 48n)) return evidence();
  const read = async (functionName: "status" | "rateLimitConfigs" | "rateLimitState") =>
    hex(
      await publicRpc("eth_call", [
        {
          to: module,
          data: encodeFunctionData({
            abi: windowed ? WINDOW_RATE_ABI : RATE_ABI,
            functionName,
            args: [id, account],
          } as Parameters<typeof encodeFunctionData>[0]),
        },
        at,
      ]),
    );
  const status = word(await read("status"));
  let used = 0n;
  if (status === 1n && !windowed) {
    const [configured, remaining, startAt] = decodeAbiParameters(
      [{ type: "uint48" }, { type: "uint48" }, { type: "uint48" }],
      await read("rateLimitConfigs"),
    );
    if (configured !== 0 || startAt !== 0 || BigInt(remaining) > maximum) return evidence();
    used = maximum - BigInt(remaining);
  } else if (status === 1n) {
    const [configured, initialCount] = decodeAbiParameters(
      [{ type: "uint48" }, { type: "uint48" }],
      await read("rateLimitConfigs"),
    );
    const [remaining, resetDate] = decodeAbiParameters(
      [{ type: "uint48" }, { type: "uint48" }],
      await read("rateLimitState"),
    );
    if (BigInt(configured) !== interval || BigInt(initialCount) !== maximum) return evidence();
    if (BigInt(remaining) > maximum) return evidence();
    // The next validation refills the quota only once chain time reaches the
    // window end. Finalized time never runs ahead of the head, so reporting a
    // reset from it is never more permissive than the contract.
    used = finalizedAt >= BigInt(resetDate) ? 0n : maximum - BigInt(remaining);
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
export function createCetaneChainPorts(
  configuration: Readonly<Record<number, Readonly<CetaneChainPortConfiguration>>>,
  options: CetaneChainPortOptions = {},
): readonly Readonly<CetaneChainCapability>[] {
  const entries = Object.entries(record(configuration));
  if (entries.length === 0 || entries.length > 64) return invalid();
  const owner = rpcOwner(options);
  return Object.freeze(
    entries.map(([key, value]) => {
      const chainId = integer(Number(key), 0, Number.MAX_SAFE_INTEGER);
      if (String(chainId) !== key) return invalid();
      const config = record(value, [
        "publicRpcUrls",
        "headers",
        "bundlerUrl",
        "bundlerHeaders",
        "paymasterUrl",
        "relayPaysGas",
        "gas",
      ]);
      if (config.relayPaysGas !== undefined && typeof config.relayPaysGas !== "boolean")
        return invalid();
      const relayPaysGas = config.relayPaysGas === true;
      // A relay-paid chain has exactly one payer: the bundler.
      if (relayPaysGas && (config.paymasterUrl !== undefined || config.bundlerUrl === undefined))
        return invalid();
      if (config.bundlerHeaders !== undefined && config.bundlerUrl === undefined) return invalid();
      const publicRpc = owner.pool(
        urls(config.publicRpcUrls),
        chainId,
        PUBLIC_METHODS,
        true,
        config.headers as Readonly<Record<string, string>> | undefined,
      );
      const bundlerRpc =
        config.bundlerUrl === undefined
          ? null
          : owner.pool(
              [url(config.bundlerUrl)],
              chainId,
              BUNDLER_METHODS,
              true,
              config.bundlerHeaders as Readonly<Record<string, string>> | undefined,
            );
      function requireBundler(): RpcRequest {
        if (!bundlerRpc) throw new OaathRpcError("oaath_rpc_bundler_unavailable");
        return bundlerRpc;
      }
      const bundler: RpcRequest = async (...args) => requireBundler()(...args);
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
        // Fees come from Cetane's default policy (2x base fee plus the priority fee).
        chain: { id: chainId, name: `Chain ${chainId}`, nativeAA: false },
        transport: custom({
          request: ({ method, params }) =>
            publicRpc(method, params as readonly unknown[] | undefined),
        }),
      });
      const readClient: KernelReadClient = {
        getChainId: async () => Number(quantity(await publicRpc("eth_chainId"))),
        getCode: async ({ address }) => hex(await publicRpc("eth_getCode", [address, "latest"])),
        getStorageAt: async ({ address, slot }) =>
          hex(await publicRpc("eth_getStorageAt", [address, slot, "latest"])),
        getBlock: async ({ blockNumber, blockTag }) => {
          const value = object(
            await publicRpc("eth_getBlockByNumber", [
              blockNumber === undefined ? blockTag : toHex(blockNumber),
              false,
            ]),
          );
          return { number: quantity(value.number), hash: hex(value.hash) };
        },
        call: async ({ to, data, blockNumber, blockTag }) => ({
          data: hex(
            await publicRpc("eth_call", [
              { to, data },
              blockNumber === undefined ? (blockTag ?? "latest") : toHex(blockNumber),
            ]),
          ),
        }),
      };
      const reads = createKernelReads(readClient);
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
        if (request.purpose === "estimate") requireBundler();
        const prepared = parsePreparedUserOperation(request.simulation.prepared);
        if (
          request.chainId !== chainId ||
          prepared.chainId !== chainId ||
          prepared.userOperation.sender !== request.account ||
          !["estimate", "sponsorship", "revalidate"].includes(request.purpose)
        )
          return invalid();
        // The caller selected the lane; this port quotes exactly its namespace.
        const nonceKey = request.nonceKey;
        const v4Key = encodeKernelV4NonceKey({
          mode: request.mode,
          validation: request.validation,
          nonceKey,
        });
        // The prepared runtime owns the actual validation mode byte. Both
        // versions use the same permission/namespace layout but different enable modes.
        const key = (BigInt(prepared.userOperation.nonce) >> 64n).toString();
        const v33Key =
          request.mode === "enable-replayable" && request.validation.kind === "permission"
            ? encodeKernelV33NonceKey({ mode: "enable", validation: request.validation, nonceKey })
            : v4Key;
        if (
          (key !== v4Key && key !== v33Key) ||
          BigInt(prepared.userOperation.nonce) !== BigInt(key) << 64n
        )
          return invalid();
        const nonce = word(
          await publicRpc("eth_call", [
            {
              to: prepared.entryPoint.address,
              data: encodeFunctionData({
                abi: entryPointAbi,
                functionName: "getNonce",
                args: [request.account, BigInt(key)],
              }),
            },
            "latest",
          ]),
        );
        if (nonce >> 64n !== BigInt(key)) return evidence();
        let quoted = gas(prepared.userOperation);
        if (request.purpose !== "revalidate" && relayPaysGas) {
          quoted = { ...quoted, maxFeePerGas: "0", maxPriorityFeePerGas: "0" };
        } else if (request.purpose !== "revalidate") {
          const fees = await client.estimateFeesPerGas().catch((error: unknown) => {
            if (error instanceof OaathRpcError) throw error;
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
        routes: Object.freeze(
          bundlerRpc === null
            ? []
            : [
                Object.freeze({
                  kind: "erc4337-bundler" as const,
                  bundler: Object.freeze({
                    async probe(request: Readonly<OaathBundlerProbeRequest>) {
                      if (request.chainId !== chainId) return invalid();
                      const supported = await bundler("eth_supportedEntryPoints");
                      if (!Array.isArray(supported)) return evidence();
                      return {
                        accepting: true,
                        chainId,
                        supportedEntryPoints: supported.map(address),
                      };
                    },
                  }),
                }),
              ],
        ),
        submission: Object.freeze({
          async open(request: Parameters<OaathChainCapability["submission"]["open"]>[0]) {
            requireBundler();
            const prepared = parsePreparedUserOperation(request.prepared);
            const signature = hex(request.signature);
            if (prepared.chainId !== chainId || request.route !== "erc4337-bundler")
              return invalid();
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
                  return {
                    userOperationHash: prepared.userOperationHash,
                    submission: { route: "erc4337-bundler", transactionHash: null },
                  };
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
        ...(paymaster === null || paymasterUrl === null
          ? {}
          : {
              sponsorship: Object.freeze({
                kind: "erc7677" as const,
                // Service identity excludes endpoint credentials; requests still
                // use the exact configured transport URL captured above.
                url: `${new URL(paymasterUrl).origin}${new URL(paymasterUrl).pathname}`.replace(
                  /\/$/u,
                  "",
                ),
                request: (request: Parameters<Erc7677ChainSponsorship["request"]>[0]) =>
                  paymaster(request.method, request.params, false),
                estimate: (request: Parameters<Erc7677ChainSponsorship["estimate"]>[0]) =>
                  estimate(parsePreparedUserOperation(request.prepared), request.userOperation),
              }),
            }),
      } satisfies OaathChainCapability);
    }),
  );
}
