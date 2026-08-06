/**
 * Final EIP-5792 orchestration over one genuine Grant provider port.
 *
 * The registry is intentionally provider-local in this child. It reserves an
 * ID before asynchronous execution work, binds the exact operation before
 * submission, and lets status perform observation only. Durable reload support
 * belongs to the later bundle-store child.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { OaathGrantProviderPort } from "../client/grant-handle.js";
import type { OaathOperationHandle } from "../client/operation-handle.js";
import {
  captureWalletCallsStatusParams,
  captureWalletGetCapabilitiesParams,
  captureWalletSendCallsParams,
  isWalletAddress,
} from "./capture.js";
import {
  DUPLICATE_ID,
  INTERNAL_ERROR,
  INVALID_PARAMS,
  OaathProviderRpcError,
  rpcFail,
  UNAUTHORIZED,
  UNKNOWN_BUNDLE_ID,
  UNSUPPORTED_METHOD,
} from "./errors.js";
import { type Eip5792CallsStatus, projectEip5792Status } from "./status.js";

export type OaathCallsStatusPresenter = (
  this: void,
  status: Readonly<Eip5792CallsStatus>,
) => void | Promise<void>;

interface CreateEip5792OrchestratorInput {
  readonly port: Readonly<OaathGrantProviderPort>;
  readonly chain: number;
  readonly showCallsStatus?: OaathCallsStatusPresenter;
}

interface AcceptedBundleRecord {
  readonly state: "accepted";
  readonly id: string;
  readonly pending: Readonly<Eip5792CallsStatus>;
}

interface OperationBoundBundleRecord {
  readonly state: "operation_bound";
  readonly id: string;
  readonly pending: Readonly<Eip5792CallsStatus>;
  readonly operation: Readonly<OaathOperationHandle> | null;
  statusRead: Promise<Readonly<Eip5792CallsStatus>> | null;
}

interface TerminalBundleRecord {
  readonly state: "terminal";
  readonly id: string;
  readonly status: Readonly<Eip5792CallsStatus>;
}

type BundleRecord = AcceptedBundleRecord | OperationBoundBundleRecord | TerminalBundleRecord;

function projectProviderStatus(
  input: Parameters<typeof projectEip5792Status>[0],
): Readonly<Eip5792CallsStatus> {
  try {
    return projectEip5792Status(input);
  } catch (error) {
    // The projector's invalid-params code describes malformed direct input.
    // Here every field is provider-owned operation evidence, so disagreement is
    // an internal observation contradiction rather than application input.
    if (error instanceof OaathProviderRpcError && error.code === INVALID_PARAMS) {
      return rpcFail(INTERNAL_ERROR);
    }
    throw error;
  }
}

export interface Eip5792Orchestrator {
  readonly sendCalls: (params: unknown) => Promise<Readonly<{ id: string }>>;
  readonly getCallsStatus: (params: unknown) => Promise<Readonly<Eip5792CallsStatus>>;
  readonly showCallsStatus: (params: unknown) => Promise<undefined>;
  readonly getCapabilities: (params: unknown) => Promise<Readonly<Record<string, unknown>>>;
}

function generatedBundleId(records: ReadonlyMap<string, BundleRecord>): string {
  const generator = globalThis.crypto;
  if (!generator || typeof generator.getRandomValues !== "function") {
    return rpcFail(INTERNAL_ERROR);
  }
  for (let attempt = 0; attempt < 8; attempt += 1) {
    let bytes: Uint8Array;
    try {
      bytes = generator.getRandomValues(new Uint8Array(32));
    } catch {
      return rpcFail(INTERNAL_ERROR);
    }
    const id = `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    if (!records.has(id)) return id;
  }
  return rpcFail(INTERNAL_ERROR);
}

function pendingStatus(id: string, chain: number): Readonly<Eip5792CallsStatus> {
  return projectProviderStatus({
    id,
    chainId: chain,
    outcome: Object.freeze({
      status: "pending",
      state: "prepared",
      transactionHash: null,
      blockNumber: null,
      outcome: null,
      reason: null,
    }),
  });
}

export function createEip5792Orchestrator(
  input: Readonly<CreateEip5792OrchestratorInput>,
): Readonly<Eip5792Orchestrator> {
  const records = new Map<string, BundleRecord>();
  const chainId = `0x${input.chain.toString(16)}`;
  // Capture the function alone so a method-style call cannot expose this
  // internal composition object as the presenter's `this` value.
  const presenter = input.showCallsStatus;

  function reserve(requestedId: string | undefined): AcceptedBundleRecord {
    const id = requestedId ?? generatedBundleId(records);
    if (records.has(id)) return rpcFail(DUPLICATE_ID);
    const accepted = Object.freeze({
      state: "accepted" as const,
      id,
      pending: pendingStatus(id, input.chain),
    });
    records.set(id, accepted);
    return accepted;
  }

  async function sendCalls(params: unknown): Promise<Readonly<{ id: string }>> {
    const captured = captureWalletSendCallsParams(params, input.chain);
    const accepted = reserve(captured.id);
    let startResolved = false;

    try {
      const account = (await input.port.account(input.chain)).toLowerCase();
      if (!isWalletAddress(account)) return rpcFail(INTERNAL_ERROR);
      if (captured.from !== undefined && captured.from !== account) {
        return rpcFail(UNAUTHORIZED);
      }

      const calls = Object.freeze(
        captured.calls.map((call) =>
          Object.freeze({
            target: call.to,
            value: BigInt(call.value ?? "0x0").toString(10),
            data: call.data ?? "0x",
          }),
        ),
      );
      const operation = await input.port.startCalls(
        Object.freeze({ chain: input.chain, calls }),
        async () => {
          if (records.get(accepted.id) !== accepted) return rpcFail(INTERNAL_ERROR);
          records.set(accepted.id, {
            state: "operation_bound",
            id: accepted.id,
            pending: accepted.pending,
            operation: null,
            statusRead: null,
          });
        },
      );
      startResolved = true;

      const bound = records.get(accepted.id);
      if (bound?.state !== "operation_bound" || bound.operation !== null) {
        return rpcFail(INTERNAL_ERROR);
      }
      records.set(accepted.id, { ...bound, operation });
      return Object.freeze({ id: accepted.id });
    } catch (error) {
      // Before binding, startCalls cannot have published, signed, or submitted
      // an operation. Once binding happened, retain the ID conservatively.
      if (!startResolved && records.get(accepted.id) === accepted) records.delete(accepted.id);
      throw error;
    }
  }

  async function observeBound(
    record: OperationBoundBundleRecord,
  ): Promise<Readonly<Eip5792CallsStatus>> {
    const operation = record.operation;
    if (operation === null) return record.pending;

    const outcome = await operation.observe();
    const status =
      outcome.status === "finalized"
        ? projectProviderStatus({
            id: record.id,
            chainId: input.chain,
            outcome,
            receipt: await operation.receipt(),
          })
        : projectProviderStatus({ id: record.id, chainId: input.chain, outcome });
    if (status.status !== 100 && records.get(record.id) === record) {
      records.set(record.id, Object.freeze({ state: "terminal", id: record.id, status }));
    }
    return status;
  }

  async function statusForId(id: string): Promise<Readonly<Eip5792CallsStatus>> {
    const record = records.get(id);
    if (record === undefined) return rpcFail(UNKNOWN_BUNDLE_ID);
    if (record.state === "accepted") return record.pending;
    if (record.state === "terminal") return record.status;
    if (record.operation === null) return record.pending;
    if (record.statusRead !== null) return record.statusRead;

    const read = observeBound(record);
    record.statusRead = read;
    try {
      return await read;
    } finally {
      if (records.get(id) === record && record.statusRead === read) record.statusRead = null;
    }
  }

  async function getCallsStatus(params: unknown): Promise<Readonly<Eip5792CallsStatus>> {
    return statusForId(captureWalletCallsStatusParams(params));
  }

  async function showCallsStatus(params: unknown): Promise<undefined> {
    const id = captureWalletCallsStatusParams(params);
    if (!records.has(id)) return rpcFail(UNKNOWN_BUNDLE_ID);
    if (presenter === undefined) return rpcFail(UNSUPPORTED_METHOD);
    await presenter(await statusForId(id));
    return undefined;
  }

  async function getCapabilities(params: unknown): Promise<Readonly<Record<string, unknown>>> {
    const captured = captureWalletGetCapabilitiesParams(params);
    const account = (await input.port.account(input.chain)).toLowerCase();
    if (!isWalletAddress(account)) return rpcFail(INTERNAL_ERROR);
    if (captured.address !== account) return rpcFail(UNAUTHORIZED);

    const requested = captured.chainIds ?? Object.freeze([chainId]);
    const result: Record<string, unknown> = Object.create(null);
    if (requested.includes(chainId)) {
      result[chainId] = Object.freeze({
        atomic: Object.freeze({ status: "supported" as const }),
      });
    }
    return Object.freeze(result);
  }

  return Object.freeze({ sendCalls, getCallsStatus, showCallsStatus, getCapabilities });
}
