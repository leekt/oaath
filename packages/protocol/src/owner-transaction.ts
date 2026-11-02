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
import { exactRecord } from "./internal/exact-record.js";

export const OAATH_OWNER_TRANSACTION_REQUEST_VERSION =
  "oaath.owner-transaction-request/v1" as const;
const HASH_DOMAIN = "@oaath/protocol:owner-transaction-request";

const fail = protocolFailure("signing_request_invalid");
const BYTES = /^0x(?:[0-9a-f]{2})*$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const MAX_UINT256 = (1n << 256n) - 1n;
/** Init code may be as large as EIP-3860 allows, twice over. */
const MAX_DATA_BYTES = 96 * 1024;

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
}

function capture(value: unknown): Readonly<OwnerTransactionRequest> {
  const record = exactRecord(
    value,
    ["version", "chainId", "from", "to", "value", "data"],
    "owner transaction request",
    new WeakSet(),
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
 * hash of chain, sender, target (or creation), value and data.
 */
export function hashOwnerTransactionRequest(value: unknown): `0x${string}` {
  const request = parseOwnerTransactionRequest(value);
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string" },
        { type: "uint256" },
        { type: "address" },
        { type: "bool" },
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
      ],
      [
        HASH_DOMAIN,
        BigInt(request.chainId),
        request.from,
        request.to === null,
        request.to ?? "0x0000000000000000000000000000000000000000",
        BigInt(request.value),
        keccak256(request.data),
      ],
    ),
  );
}
