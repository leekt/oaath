/**
 * Final EIP-5792 status projection for one exact OAAth operation.
 *
 * @author taek <leekt216@gmail.com>
 */
import type {
  OaathOperationLog,
  OaathOperationOutcome,
  OaathOperationReceipt,
} from "../client/operation-handle.js";
import { INVALID_PARAMS, rpcFail } from "./errors.js";
import type { OaathWalletCallResultCapabilities } from "./result-capabilities.js";

const DECIMAL_UINT = /^(?:0|[1-9][0-9]*)$/u;

export type Eip5792StatusCode = 100 | 200 | 400 | 500;

export interface Eip5792StatusReceipt {
  readonly logs: readonly Readonly<OaathOperationLog>[];
  readonly status: "0x1" | "0x0";
  readonly blockHash: `0x${string}`;
  readonly blockNumber: `0x${string}`;
  readonly gasUsed: `0x${string}`;
  readonly transactionHash: `0x${string}`;
}

interface Eip5792StatusBase {
  readonly version: "2.0.0";
  readonly id: string;
  readonly chainId: `0x${string}`;
  readonly atomic: true;
  readonly capabilities?: Readonly<OaathWalletCallResultCapabilities>;
}

export type Eip5792CallsStatus =
  | (Eip5792StatusBase & {
      readonly status: 100 | 400;
    })
  | (Eip5792StatusBase & {
      readonly status: 200 | 500;
      readonly receipts: readonly [Readonly<Eip5792StatusReceipt>];
    });

export interface ProjectEip5792StatusInput {
  /** The provider bundle id, returned byte-for-byte without normalization. */
  readonly id: string;
  readonly chainId: number;
  readonly outcome: Readonly<OaathOperationOutcome>;
  readonly receipt?: Readonly<OaathOperationReceipt> | null;
  readonly resultCapabilities?: Readonly<OaathWalletCallResultCapabilities> | null;
}

function invalidEvidence(): never {
  return rpcFail(INVALID_PARAMS, "operation status evidence is contradictory");
}

function quantity(value: string): `0x${string}` {
  if (!DECIMAL_UINT.test(value)) return invalidEvidence();
  return `0x${BigInt(value).toString(16)}`;
}

function immutableLog(log: Readonly<OaathOperationLog>): Readonly<OaathOperationLog> {
  return Object.freeze({
    address: log.address,
    topics: Object.freeze([...log.topics]),
    data: log.data,
  });
}

/**
 * Projects already-owned operation evidence without observing or submitting.
 * Receipt logs are preserved exactly in supplied order; their relevance is an
 * invariant of the receipt owner, not something this projection can infer.
 */
export function projectEip5792Status(
  input: Readonly<ProjectEip5792StatusInput>,
): Readonly<Eip5792CallsStatus> {
  if (!Number.isSafeInteger(input.chainId) || input.chainId < 1) return invalidEvidence();
  const base = {
    version: "2.0.0",
    id: input.id,
    chainId: `0x${input.chainId.toString(16)}` as const,
    atomic: true,
    ...(input.resultCapabilities == null ? {} : { capabilities: input.resultCapabilities }),
  } as const;
  const outcome = input.outcome;

  // Unresolved observations remain pending even when retained inclusion
  // evidence exists. Included is not terminal finality.
  if (outcome.status === "pending" || outcome.status === "unreadable") {
    return Object.freeze({ ...base, status: 100 });
  }
  if (outcome.status === "dropped") {
    if (outcome.state !== "dropped") return invalidEvidence();
    return Object.freeze({ ...base, status: 400 });
  }
  if (outcome.status === "superseded") {
    if (outcome.state !== "superseded") return invalidEvidence();
    // Nonce advancement proves this identity cannot execute in the future, but
    // without its receipt it does not prove whether it executed before that
    // advancement. Do not project the ambiguity as a failed call.
    return Object.freeze({ ...base, status: 100 });
  }
  if (outcome.status === "abandoned") {
    if (outcome.state !== "abandoned") return invalidEvidence();
    return Object.freeze({ ...base, status: 400 });
  }

  const receipt = input.receipt;
  const transactionHash = outcome.transactionHash;
  const blockNumber = outcome.blockNumber;
  const operationResult = outcome.outcome;
  if (
    outcome.state !== "finalized" ||
    transactionHash === null ||
    blockNumber === null ||
    operationResult === null ||
    receipt === undefined ||
    receipt === null
  ) {
    return invalidEvidence();
  }
  if (operationResult !== "success" && operationResult !== "reverted") {
    return invalidEvidence();
  }

  const canonicalBlockNumber = quantity(blockNumber);
  if (
    receipt.transactionHash !== transactionHash ||
    quantity(receipt.blockNumber) !== canonicalBlockNumber ||
    receipt.status !== operationResult
  ) {
    return invalidEvidence();
  }

  const projectedReceipt = Object.freeze({
    logs: Object.freeze(receipt.logs.map(immutableLog)),
    status: operationResult === "success" ? ("0x1" as const) : ("0x0" as const),
    blockHash: receipt.blockHash,
    blockNumber: canonicalBlockNumber,
    gasUsed: quantity(receipt.gasUsed),
    transactionHash,
  });
  return Object.freeze({
    ...base,
    status: operationResult === "success" ? (200 as const) : (500 as const),
    receipts: Object.freeze([projectedReceipt] as const),
  });
}
