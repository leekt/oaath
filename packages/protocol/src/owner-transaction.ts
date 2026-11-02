/**
 * Current-version owner-transaction wire owner: one exact plain transaction an
 * OAAth signer's own wallet sends from the portal (a factory call with value,
 * a contract creation, an EntryPoint `handleOps`). It is not a UserOperation:
 * the wallet signs and broadcasts it, and the portal returns its hash.
 *
 * `hashOwnerTransactionRequest` is the identity an app holds before anything
 * is sent. Nothing here signs, sends, or reads a chain.
 *
 * @author taek <leekt216@gmail.com>
 */
import { encodeAbiParameters, keccak256 } from "cetane/utils";
import { captureAddress } from "./address.js";
import { capturedByProtocol, protocolFailure } from "./errors.js";
import {
  captureDenseArray,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "./internal/exact-record.js";

export const OAATH_OWNER_TRANSACTION_REQUEST_VERSION =
  "oaath.owner-transaction-request/v1" as const;
const HASH_DOMAIN = "@oaath/protocol:owner-transaction-request";

const fail = protocolFailure("signing_request_invalid");
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const MAX_UINT256 = (1n << 256n) - 1n;
/** Init code may be as large as EIP-3860 allows, twice over. */
const MAX_DATA_BYTES = 96 * 1024;
const MAX_NAME = 64;
const MAX_SYMBOL = 12;
const MAX_URL = 256;
const MAX_URLS = 4;

/**
 * EIP-3085 metadata for a chain the sender's wallet may not know yet. The
 * portal adds it to the wallet only after `wallet_switchEthereumChain` reports
 * the chain unrecognized (4902). URLs are canonical `https` with no
 * credentials, query, or fragment.
 */
export interface OwnerTransactionChain {
  readonly name: string;
  readonly nativeCurrency: {
    readonly name: string;
    readonly symbol: string;
    readonly decimals: 18;
  };
  /** One to four RPC URLs. */
  readonly rpcUrls: readonly string[];
  /** Up to four block explorer URLs, when given. */
  readonly blockExplorerUrls?: readonly string[];
}

export interface OwnerTransactionRequest {
  readonly version: typeof OAATH_OWNER_TRANSACTION_REQUEST_VERSION;
  readonly chainId: number;
  /** The signer's own wallet address that sends it. */
  readonly from: `0x${string}`;
  /** Null for a contract creation. */
  readonly to: `0x${string}` | null;
  /** Canonical decimal uint256 wei. */
  readonly value: string;
  readonly data: `0x${string}`;
  /** Metadata to add the chain to a wallet that does not know it. */
  readonly chain?: Readonly<OwnerTransactionChain>;
}

function text(value: unknown, maximum: number, label: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value !== value.trim()
  )
    return fail(`${label} must be trimmed text of at most ${maximum} characters`);
  return value;
}

function httpsUrl(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > MAX_URL || /[?#]/u.test(value))
    return fail(`${label} must be a canonical https URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return fail(`${label} must be a canonical https URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.href !== value)
    return fail(`${label} must be a canonical https URL`);
  return value;
}

function urls(value: unknown, minimum: number, label: string, context: WeakSet<object>) {
  const entries = captureDenseArray(value, label, context, fail);
  if (entries.length < minimum || entries.length > MAX_URLS)
    return fail(`${label} must list ${minimum} to ${MAX_URLS} URLs`);
  return Object.freeze(entries.map((entry) => httpsUrl(entry, label)));
}

function captureChain(value: unknown, context: WeakSet<object>): Readonly<OwnerTransactionChain> {
  const label = "owner transaction chain metadata";
  const captured = captureRecord(value, label, context, fail);
  const record = exactCapturedRecord(
    captured,
    Object.hasOwn(captured, "blockExplorerUrls")
      ? ["name", "nativeCurrency", "rpcUrls", "blockExplorerUrls"]
      : ["name", "nativeCurrency", "rpcUrls"],
    label,
    fail,
  );
  const currency = exactRecord(
    record.nativeCurrency,
    ["name", "symbol", "decimals"],
    "owner transaction native currency",
    context,
    fail,
  );
  if (currency.decimals !== 18)
    return fail("owner transaction native currency must have 18 decimals");
  return Object.freeze({
    name: text(record.name, MAX_NAME, "owner transaction chain name"),
    nativeCurrency: Object.freeze({
      name: text(currency.name, MAX_NAME, "owner transaction native currency name"),
      symbol: text(currency.symbol, MAX_SYMBOL, "owner transaction native currency symbol"),
      decimals: 18 as const,
    }),
    rpcUrls: urls(record.rpcUrls, 1, "owner transaction RPC URL", context),
    ...(Object.hasOwn(record, "blockExplorerUrls")
      ? {
          blockExplorerUrls: urls(
            record.blockExplorerUrls,
            1,
            "owner transaction block explorer URL",
            context,
          ),
        }
      : {}),
  });
}

function capture(value: unknown): Readonly<OwnerTransactionRequest> {
  const context = new WeakSet<object>();
  const captured = captureRecord(value, "owner transaction request", context, fail);
  const keys = ["version", "chainId", "from", "to", "value", "data"];
  const record = exactCapturedRecord(
    captured,
    Object.hasOwn(captured, "chain") ? [...keys, "chain"] : keys,
    "owner transaction request",
    fail,
  );
  if (record.version !== OAATH_OWNER_TRANSACTION_REQUEST_VERSION)
    return fail("owner transaction request version is unsupported");
  if (
    typeof record.chainId !== "number" ||
    !Number.isSafeInteger(record.chainId) ||
    record.chainId < 1
  )
    return fail("owner transaction chain is invalid");
  const from = captureAddress(record.from, "owner transaction sender", fail);
  const to =
    record.to === null ? null : captureAddress(record.to, "owner transaction target", fail);
  if (
    typeof record.value !== "string" ||
    !DECIMAL_UINT.test(record.value) ||
    BigInt(record.value) > MAX_UINT256
  )
    return fail("owner transaction value must be a canonical decimal uint256");
  const data = record.data;
  if (typeof data !== "string" || !BYTES.test(data) || data.length > 2 + MAX_DATA_BYTES * 2)
    return fail("owner transaction data must be bounded canonical lowercase bytes");
  if (to === null && data === "0x") return fail("a contract creation needs init code");
  return Object.freeze({
    version: OAATH_OWNER_TRANSACTION_REQUEST_VERSION,
    chainId: record.chainId,
    from,
    to,
    value: record.value,
    data: data as `0x${string}`,
    ...(Object.hasOwn(record, "chain") ? { chain: captureChain(record.chain, context) } : {}),
  });
}

/** Captures one exact owner-transaction request. */
export function parseOwnerTransactionRequest(value: unknown): Readonly<OwnerTransactionRequest> {
  return capturedByProtocol("signing_request_invalid", "owner transaction request is invalid", () =>
    capture(value),
  );
}

/**
 * The request's identity, known before the wallet is asked: a domain-separated
 * hash of chain, sender, target (or creation), value and data, and of the
 * chain metadata when present.
 */
export function hashOwnerTransactionRequest(value: unknown): `0x${string}` {
  const request = parseOwnerTransactionRequest(value);
  const types = [
    { type: "string" },
    { type: "uint256" },
    { type: "address" },
    { type: "bool" },
    { type: "address" },
    { type: "uint256" },
    { type: "bytes32" },
  ] as const;
  const values = [
    HASH_DOMAIN,
    BigInt(request.chainId),
    request.from,
    request.to === null,
    request.to ?? "0x0000000000000000000000000000000000000000",
    BigInt(request.value),
    keccak256(request.data),
  ] as const;
  const chain = request.chain;
  if (chain === undefined) return keccak256(encodeAbiParameters(types, values));
  return keccak256(
    encodeAbiParameters(
      [...types, { type: "bytes32" }],
      [
        ...values,
        keccak256(
          encodeAbiParameters(
            [
              { type: "string" },
              { type: "string" },
              { type: "string" },
              { type: "uint8" },
              { type: "string[]" },
              { type: "bool" },
              { type: "string[]" },
            ],
            [
              chain.name,
              chain.nativeCurrency.name,
              chain.nativeCurrency.symbol,
              chain.nativeCurrency.decimals,
              chain.rpcUrls,
              chain.blockExplorerUrls !== undefined,
              chain.blockExplorerUrls ?? [],
            ],
          ),
        ),
      ],
    ),
  );
}
