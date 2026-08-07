/**
 * `@oaath/sdk/viem` exposes one active Grant as a narrow EIP-1193 provider.
 *
 * `eth_accounts`, `eth_requestAccounts`, `eth_chainId`, and
 * `eth_sendTransaction` retain their existing Grant-backed behavior. Final
 * EIP-5792 wallet-call orchestration lives behind this facade and uses the same
 * Grant authority, operation runner, and exact observation handle.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureDenseArray,
  captureRecord,
  type ExactRecord,
} from "@oaath/protocol";
import { clientFail } from "./client/errors.js";
import { grantProviderPort, type OaathGrantHandle } from "./client/grant-handle.js";
import { createEip5792Orchestrator, type OaathCallsStatusPresenter } from "./provider/eip5792.js";
import {
  INTERNAL_ERROR,
  INVALID_PARAMS,
  invalidProviderParams,
  mapProviderFailure,
  rpcFail,
  UNSUPPORTED_METHOD,
} from "./provider/errors.js";

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
  /** Optional wallet-owned UI. It receives only a frozen public status value. */
  readonly showCallsStatus?: OaathCallsStatusPresenter;
}

interface CapturedProviderRequest {
  readonly method: string;
  readonly params?: unknown;
}

function lower(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function acceptOnly(record: ExactRecord, keys: readonly string[]): void {
  for (const key of Object.keys(record)) {
    if (!keys.includes(key)) invalidProviderParams();
  }
}

function captureProviderRequest(args: unknown): CapturedProviderRequest {
  const record = captureRecord(args, "provider request", new WeakSet(), invalidProviderParams);
  acceptOnly(record, ["method", "params"]);
  if (!Object.hasOwn(record, "method") || typeof record.method !== "string") {
    return invalidProviderParams();
  }
  return Object.freeze({
    method: record.method,
    ...(Object.hasOwn(record, "params") ? { params: record.params } : {}),
  });
}

/** One eth_sendTransaction request, captured exactly; gas fields are refused. */
function captureTransaction(
  params: unknown,
  account: `0x${string}`,
): Readonly<{ target: `0x${string}`; value: string; data: `0x${string}` }> {
  const context: CaptureContext = new WeakSet();
  const entries = captureDenseArray(
    params,
    "eth_sendTransaction params",
    context,
    invalidProviderParams,
  );
  if (entries.length !== 1) return invalidProviderParams();
  const record = captureRecord(
    entries[0],
    "eth_sendTransaction transaction",
    context,
    invalidProviderParams,
  );
  acceptOnly(record, ["from", "to", "value", "data"]);

  const from = record.from;
  if (typeof from !== "string" || !ADDRESS.test(from) || lower(from) !== account) {
    return rpcFail(INVALID_PARAMS);
  }
  const to = record.to;
  if (typeof to !== "string" || !ADDRESS.test(to)) return rpcFail(INVALID_PARAMS);
  const value = record.value ?? "0x0";
  if (typeof value !== "string" || !QUANTITY.test(value)) return rpcFail(INVALID_PARAMS);
  const data = record.data ?? "0x";
  if (typeof data !== "string" || !BYTES.test(data)) return rpcFail(INVALID_PARAMS);
  return Object.freeze({
    target: lower(to),
    value: BigInt(value).toString(10),
    data: lower(data),
  });
}

function captureProviderInput(input: unknown): Readonly<{
  grant: Readonly<OaathGrantHandle>;
  chain: number;
  showCallsStatus?: OaathCallsStatusPresenter;
}> {
  const fail = (message: string): never => clientFail("oaath_client_input_invalid", message);
  const record = captureRecord(input, "OAAth provider input", new WeakSet(), fail);
  for (const key of Object.keys(record)) {
    if (key !== "grant" && key !== "chain" && key !== "showCallsStatus") fail("unknown field");
  }
  if (!Object.hasOwn(record, "grant") || !Object.hasOwn(record, "chain")) {
    return fail("missing field");
  }
  const chain = record.chain;
  if (typeof chain !== "number" || !Number.isSafeInteger(chain) || chain < 1) {
    return fail("provider chain is invalid");
  }
  const grant = record.grant;
  // This lookup, rather than a structural method check, is the proof that the
  // handle was minted by the Grant owner in this SDK instance.
  grantProviderPort(grant);
  const showCallsStatus = Object.hasOwn(record, "showCallsStatus")
    ? record.showCallsStatus
    : undefined;
  if (showCallsStatus !== undefined && typeof showCallsStatus !== "function") {
    return fail("showCallsStatus must be a function");
  }
  return Object.freeze({
    grant: grant as Readonly<OaathGrantHandle>,
    chain,
    ...(showCallsStatus === undefined
      ? {}
      : { showCallsStatus: showCallsStatus as OaathCallsStatusPresenter }),
  });
}

/** Construct one Grant-backed EIP-1193 provider. */
export function oaathProvider(input: Readonly<OaathProviderInput>): OaathEip1193Provider {
  const captured = captureProviderInput(input);
  const { grant, chain } = captured;
  const port = grantProviderPort(grant);
  const wallet = createEip5792Orchestrator({
    port,
    chain,
    ...(captured.showCallsStatus === undefined
      ? {}
      : { showCallsStatus: captured.showCallsStatus }),
  });

  async function account(): Promise<`0x${string}`> {
    const value = (await port.account(chain)).toLowerCase();
    if (!ADDRESS.test(value)) return rpcFail(INTERNAL_ERROR);
    return value as `0x${string}`;
  }

  async function accounts(): Promise<readonly [`0x${string}`]> {
    return Object.freeze([await account()] as const);
  }

  async function sendTransaction(params: unknown): Promise<`0x${string}`> {
    const call = captureTransaction(params, await account());
    const operation = await grant.sendCalls({ chain, calls: [call] });
    const outcome = await operation.wait();
    // A mined-but-reverted operation still has the transaction hash expected by
    // eth_sendTransaction. Anything without conclusive inclusion has no hash to
    // invent at this boundary.
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
      try {
        const request = captureProviderRequest(args);
        switch (request.method) {
          case "eth_chainId":
            return `0x${chain.toString(16)}`;
          case "eth_accounts":
          case "eth_requestAccounts":
            return await accounts();
          case "eth_sendTransaction":
            return await sendTransaction(request.params);
          case "wallet_sendCalls":
            return await wallet.sendCalls(request.params);
          case "wallet_getCallsStatus":
            return await wallet.getCallsStatus(request.params);
          case "wallet_showCallsStatus":
            return await wallet.showCallsStatus(request.params);
          case "wallet_getCapabilities":
            return await wallet.getCapabilities(request.params);
          default:
            return rpcFail(UNSUPPORTED_METHOD);
        }
      } catch (error) {
        return mapProviderFailure(error);
      }
    },
  });
}
