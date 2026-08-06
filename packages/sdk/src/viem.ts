/**
 * `@oaath/sdk/viem` — one active Grant as an EIP-1193 provider, so any
 * viem-based application can execute through OAAth without learning its
 * vocabulary:
 *
 * ```ts
 * import { createWalletClient, custom } from "viem";
 * import { oaathProvider } from "@oaath/sdk/viem";
 *
 * const provider = oaathProvider({ grant, chain: 421614 });
 * const wallet = createWalletClient({ transport: custom(provider) });
 * const hash = await wallet.sendTransaction({ account, to, value, data, chain: null });
 * ```
 *
 * The provider is deliberately narrow and honest:
 *
 * - `eth_accounts` / `eth_requestAccounts` answer the Grant's derived smart
 *   account — a chain-read-proven fact, never an assertion.
 * - `eth_sendTransaction` rides `grant.sendCalls`, waits for the operation to
 *   finalize, and returns the real inclusion transaction hash, so receipts
 *   resolve against evidence instead of a UserOperation hash no node knows.
 *   A mined-but-reverted call still returns its hash, exactly like an EOA.
 * - EIP-5792 `wallet_sendCalls` maps a call bundle onto one `sendCalls`
 *   operation and answers `wallet_getCallsStatus` from the operation's own
 *   evidence: 100 while unresolved, 200 once finalized, with the receipt read
 *   from the chain and bound to the recorded inclusion. Capabilities are not
 *   emulated: `wallet_getCapabilities` answers atomic-only, nothing more.
 * - Every other method is refused, not emulated. Reads belong to the
 *   application's own public client, and signing methods would impersonate an
 *   authority this scoped session does not hold.
 *
 * All the Grant's own boundaries hold unchanged underneath: scope coverage,
 * per-call value limits, the per-chain operation limit, and expiry all deny
 * exactly as they would through `sendCalls` directly.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureRecord } from "@oaath/protocol";
import { clientFail, exactClientRecord } from "./client/errors.js";
import type { OaathGrantHandle } from "./client/grant-handle.js";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const BYTES = /^0x(?:[0-9a-fA-F]{2})*$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;

/** The minimal EIP-1193 surface viem's `custom` transport consumes. */
export interface OaathEip1193Provider {
  readonly request: (args: { method: string; params?: unknown }) => Promise<unknown>;
}

export interface OaathProviderInput {
  readonly grant: Readonly<OaathGrantHandle>;
  /** The one chain this provider speaks for; a second chain is a second provider. */
  readonly chain: number;
}

/** EIP-1193 error codes for the refusals this provider makes. */
const UNSUPPORTED_METHOD = 4200;
const INVALID_PARAMS = -32602;

class OaathProviderRpcError extends Error {
  readonly code: number;

  constructor(code: number, message: string) {
    super(message);
    this.name = "OaathProviderRpcError";
    this.code = code;
  }
}

function rpcFail(code: number, message: string): never {
  throw new OaathProviderRpcError(code, message);
}

function lower(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

/** One eth_sendTransaction request, captured exactly; gas fields are refused. */
function captureTransaction(
  params: unknown,
  account: `0x${string}`,
): Readonly<{ target: `0x${string}`; value: string; data: `0x${string}` }> {
  if (!Array.isArray(params) || params.length !== 1) {
    return rpcFail(INVALID_PARAMS, "eth_sendTransaction takes exactly one transaction");
  }
  const context: CaptureContext = new WeakSet();
  const record = captureRecord(params[0], "eth_sendTransaction transaction", context, (message) =>
    rpcFail(INVALID_PARAMS, message),
  );
  // `value` and `data` are optional; anything else — gas, fee, and nonce
  // fields included — is refused, because the service quotes gas and the
  // durable journal owns the nonce, and silently ignoring a field a caller
  // set is worse than a refusal.
  for (const key of Object.keys(record)) {
    if (key !== "from" && key !== "to" && key !== "value" && key !== "data") {
      return rpcFail(INVALID_PARAMS, `eth_sendTransaction does not accept ${key}`);
    }
  }
  const from = record.from;
  if (typeof from !== "string" || lower(from) !== account) {
    return rpcFail(INVALID_PARAMS, "transaction from is not the Grant's account");
  }
  const to = record.to;
  if (typeof to !== "string" || !ADDRESS.test(to)) {
    return rpcFail(INVALID_PARAMS, "transaction to must be an address; deploys are not covered");
  }
  const value = record.value ?? "0x0";
  if (typeof value !== "string" || !QUANTITY.test(value)) {
    return rpcFail(INVALID_PARAMS, "transaction value must be a hex quantity");
  }
  const data = record.data ?? "0x";
  if (typeof data !== "string" || !BYTES.test(data)) {
    return rpcFail(INVALID_PARAMS, "transaction data must be hex bytes");
  }
  return Object.freeze({
    target: lower(to),
    value: BigInt(value).toString(10),
    data: lower(data),
  });
}

export function oaathProvider(input: Readonly<OaathProviderInput>): OaathEip1193Provider {
  const record = exactClientRecord(
    input,
    ["grant", "chain"],
    "OAAth provider input",
    new WeakSet(),
  );
  const chainValue = record.chain;
  if (typeof chainValue !== "number" || !Number.isSafeInteger(chainValue) || chainValue < 1) {
    return clientFail("oaath_client_input_invalid", "provider chain is invalid");
  }
  const chain: number = chainValue;
  const grant = record.grant as Readonly<OaathGrantHandle>;
  if (grant === null || typeof grant !== "object" || typeof grant.sendCalls !== "function") {
    return clientFail("oaath_client_input_invalid", "provider grant is not a Grant handle");
  }

  async function accounts(): Promise<readonly [`0x${string}`]> {
    return Object.freeze([await grant.account(chain)] as const);
  }

  /** EIP-5792 bundles by provider-minted id; ids grant nothing. */
  const bundles = new Map<string, Awaited<ReturnType<OaathGrantHandle["sendCalls"]>>>();

  function bundleId(): string {
    const generator = (globalThis as { readonly crypto?: { readonly randomUUID?: () => string } })
      .crypto;
    if (!generator || typeof generator.randomUUID !== "function") {
      return clientFail("oaath_client_capability_invalid", "crypto.randomUUID is unavailable");
    }
    return `0x${generator.randomUUID().replaceAll("-", "")}`;
  }

  /** One EIP-5792 wallet_sendCalls request onto one Grant operation. */
  async function sendCallsBundle(params: unknown): Promise<Readonly<{ id: string }>> {
    if (!Array.isArray(params) || params.length !== 1) {
      return rpcFail(INVALID_PARAMS, "wallet_sendCalls takes exactly one bundle");
    }
    const context: CaptureContext = new WeakSet();
    const bundle = captureRecord(params[0], "wallet_sendCalls bundle", context, (message) =>
      rpcFail(INVALID_PARAMS, message),
    );
    for (const key of Object.keys(bundle)) {
      if (!["version", "chainId", "from", "atomicRequired", "calls"].includes(key)) {
        return rpcFail(INVALID_PARAMS, `wallet_sendCalls does not accept ${key}`);
      }
    }
    if (bundle.version !== undefined && bundle.version !== "2.0.0") {
      return rpcFail(INVALID_PARAMS, "wallet_sendCalls version must be 2.0.0");
    }
    if (bundle.chainId !== undefined && bundle.chainId !== `0x${chain.toString(16)}`) {
      return rpcFail(INVALID_PARAMS, "wallet_sendCalls chainId is not this provider's chain");
    }
    // Every Grant operation is atomic by construction, so atomicRequired is
    // satisfiable in either form.
    if (bundle.atomicRequired !== undefined && typeof bundle.atomicRequired !== "boolean") {
      return rpcFail(INVALID_PARAMS, "wallet_sendCalls atomicRequired must be a boolean");
    }
    const account = await grant.account(chain);
    if (
      bundle.from !== undefined &&
      (typeof bundle.from !== "string" || lower(bundle.from) !== account)
    ) {
      return rpcFail(INVALID_PARAMS, "bundle from is not the Grant's account");
    }
    if (!Array.isArray(bundle.calls) || bundle.calls.length < 1) {
      return rpcFail(INVALID_PARAMS, "wallet_sendCalls requires at least one call");
    }
    const calls = bundle.calls.map((entry) => {
      const call = captureRecord(entry, "wallet_sendCalls call", context, (message) =>
        rpcFail(INVALID_PARAMS, message),
      );
      for (const key of Object.keys(call)) {
        if (!["to", "value", "data"].includes(key)) {
          return rpcFail(INVALID_PARAMS, `wallet_sendCalls call does not accept ${key}`);
        }
      }
      const to = call.to;
      if (typeof to !== "string" || !ADDRESS.test(to)) {
        return rpcFail(INVALID_PARAMS, "call to must be an address; deploys are not covered");
      }
      const value = call.value ?? "0x0";
      if (typeof value !== "string" || !QUANTITY.test(value)) {
        return rpcFail(INVALID_PARAMS, "call value must be a hex quantity");
      }
      const data = call.data ?? "0x";
      if (typeof data !== "string" || !BYTES.test(data)) {
        return rpcFail(INVALID_PARAMS, "call data must be hex bytes");
      }
      return Object.freeze({
        target: lower(to),
        value: BigInt(value).toString(10),
        data: lower(data),
      });
    });
    const operation = await grant.sendCalls({ chain, calls });
    const id = bundleId();
    bundles.set(id, operation);
    return Object.freeze({ id });
  }

  /** EIP-5792 wallet_getCallsStatus from the operation's own evidence. */
  async function getCallsStatus(params: unknown): Promise<unknown> {
    if (!Array.isArray(params) || params.length !== 1 || typeof params[0] !== "string") {
      return rpcFail(INVALID_PARAMS, "wallet_getCallsStatus takes exactly one id");
    }
    const operation = bundles.get(params[0]);
    if (operation === undefined) {
      return rpcFail(INVALID_PARAMS, "unknown call bundle id");
    }
    const outcome = await operation.observe();
    const base = {
      version: "2.0.0",
      id: params[0],
      chainId: `0x${chain.toString(16)}`,
      // One UserOperation executes the whole bundle; partial execution is not
      // expressible.
      atomic: true,
    };
    if (outcome.status !== "finalized" || outcome.transactionHash === null) {
      // 100: pending or unresolved. Nothing here invents completion — a
      // dropped operation surfaces once its replacement evidence is terminal.
      return Object.freeze({ ...base, status: outcome.status === "dropped" ? 500 : 100 });
    }
    // 200: confirmed on chain. The receipt itself states success or revert,
    // exactly like EIP-5792 requires; it is read fresh and evidence-bound.
    const receipt = await operation.receipt();
    return Object.freeze({
      ...base,
      status: 200,
      receipts: Object.freeze([
        Object.freeze({
          logs: receipt.logs,
          status: receipt.status === "success" ? "0x1" : "0x0",
          blockHash: receipt.blockHash,
          blockNumber: `0x${BigInt(receipt.blockNumber).toString(16)}`,
          gasUsed: `0x${BigInt(receipt.gasUsed).toString(16)}`,
          transactionHash: receipt.transactionHash,
        }),
      ]),
    });
  }

  async function sendTransaction(params: unknown): Promise<`0x${string}`> {
    const call = captureTransaction(params, await grant.account(chain));
    const operation = await grant.sendCalls({ chain, calls: [call] });
    const outcome = await operation.wait();
    // A transaction hash exists only for evidence-backed inclusion; anything
    // else stays a structured refusal rather than an invented pending hash.
    // A mined-but-reverted call still returns its hash, exactly like an EOA.
    if (outcome.status !== "finalized" || outcome.transactionHash === null) {
      return clientFail(
        "oaath_client_observation_unavailable",
        "the operation did not conclusively finalize",
        outcome.reason,
      );
    }
    return outcome.transactionHash;
  }

  return Object.freeze({
    async request(args: { method: string; params?: unknown }): Promise<unknown> {
      const request = exactClientRecord(
        args,
        args !== null && typeof args === "object" && "params" in args
          ? ["method", "params"]
          : ["method"],
        "provider request",
        new WeakSet(),
      );
      switch (request.method) {
        case "eth_chainId":
          return `0x${chain.toString(16)}`;
        case "eth_accounts":
        case "eth_requestAccounts":
          return accounts();
        case "eth_sendTransaction":
          return sendTransaction(request.params);
        case "wallet_sendCalls":
          return sendCallsBundle(request.params);
        case "wallet_getCallsStatus":
          return getCallsStatus(request.params);
        case "wallet_getCapabilities":
          // Honest and minimal: every bundle executes atomically in one
          // operation; no other capability is claimed.
          return Object.freeze({
            [`0x${chain.toString(16)}`]: Object.freeze({
              atomic: Object.freeze({ status: "supported" }),
            }),
          });
        default:
          // Reads belong to the application's public client, and signing
          // methods would impersonate authority this session does not hold.
          return rpcFail(
            UNSUPPORTED_METHOD,
            `the OAAth provider does not serve ${String(request.method)}`,
          );
      }
    },
  });
}
