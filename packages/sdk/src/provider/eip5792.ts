/**
 * Final EIP-5792 orchestration over one genuine Grant provider port.
 *
 * WalletCallBundleStore owns durable request identity and lifecycle. Provider
 * memory only coordinates calls currently executing in this orchestrator;
 * every later status read resolves the durable bundle and exact Operation.
 *
 * @author taek <leekt216@gmail.com>
 */
import type {
  OaathGrantProviderPort,
  OaathProviderOperationPointer,
} from "../client/grant-handle.js";
import { kernelV4Deployment } from "../kernel-v4.js";
import type {
  WalletCallBundleKey,
  WalletCallBundleStoreRecord,
} from "../persistence/interfaces.js";
import { WALLET_CALL_BUNDLE_PUBLICATION_LEASE_SECONDS } from "./bundle-store.js";
import { advertiseWalletCapabilities, applyWalletCapabilities } from "./capabilities.js";
import {
  captureWalletCallsStatusParams,
  captureWalletGetCapabilitiesParams,
  captureWalletSendCallsParams,
  hashCapturedWalletSendCallsRequest,
  hashWalletCallBundleProvenance,
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

const GENERATED_ID_ATTEMPTS = 8;
const HASH = /^0x[0-9a-f]{64}$/u;

export type OaathCallsStatusPresenter = (
  this: void,
  status: Readonly<Eip5792CallsStatus>,
) => void | Promise<void>;

interface CreateEip5792OrchestratorInput {
  readonly port: Readonly<OaathGrantProviderPort>;
  readonly chain: number;
  readonly showCallsStatus?: OaathCallsStatusPresenter;
}

function projectProviderStatus(
  input: Parameters<typeof projectEip5792Status>[0],
): Readonly<Eip5792CallsStatus> {
  try {
    return projectEip5792Status(input);
  } catch (error) {
    // Every field here is provider-owned operation evidence, so disagreement is
    // an internal contradiction rather than malformed application input.
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

function generatedBundleId(): string {
  const generator = globalThis.crypto;
  if (!generator || typeof generator.getRandomValues !== "function") {
    return rpcFail(INTERNAL_ERROR);
  }
  const bytes = new Uint8Array(32);
  try {
    generator.getRandomValues(bytes);
  } catch {
    return rpcFail(INTERNAL_ERROR);
  }
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
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

function offchainFailureStatus(id: string, chain: number): Readonly<Eip5792CallsStatus> {
  return projectProviderStatus({
    id,
    chainId: chain,
    outcome: Object.freeze({
      status: "abandoned",
      state: "abandoned",
      transactionHash: null,
      blockNumber: null,
      outcome: null,
      reason: "submission_not_attempted",
    }),
  });
}

function sameOperationPointer(
  left: OaathProviderOperationPointer,
  right: OaathProviderOperationPointer,
): boolean {
  return (
    left.identity.kind === right.identity.kind &&
    left.identity.grantId === right.identity.grantId &&
    left.identity.chainId === right.identity.chainId &&
    left.identity.entryPoint === right.identity.entryPoint &&
    left.identity.account === right.identity.account &&
    left.identity.nonce === right.identity.nonce &&
    left.identity.userOperationHash === right.identity.userOperationHash &&
    left.identity.requestHash === right.identity.requestHash
  );
}

export function createEip5792Orchestrator(
  input: Readonly<CreateEip5792OrchestratorInput>,
): Readonly<Eip5792Orchestrator> {
  const chainId = `0x${input.chain.toString(16)}`;
  const presenter = input.showCallsStatus;
  const store = input.port.walletCallBundles;

  function now(): number {
    const value = input.port.now();
    if (
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      Object.is(value, -0) ||
      value < 0
    ) {
      return rpcFail(INTERNAL_ERROR);
    }
    return value;
  }

  async function account(): Promise<`0x${string}`> {
    const value = (await input.port.account(input.chain)).toLowerCase();
    if (!isWalletAddress(value)) return rpcFail(INTERNAL_ERROR);
    return value;
  }

  function key(id: string, accountAddress: `0x${string}`): Readonly<WalletCallBundleKey> {
    if (
      !HASH.test(input.port.providerScopeId) ||
      !isWalletAddress(accountAddress) ||
      input.port.grantId.length < 1 ||
      input.port.grantId.length > 256 ||
      input.port.grantId !== input.port.grantId.trim()
    ) {
      return rpcFail(INTERNAL_ERROR);
    }
    return Object.freeze({
      providerScopeId: input.port.providerScopeId as `0x${string}`,
      account: accountAddress,
      id,
    });
  }

  async function reserve(
    captured: ReturnType<typeof captureWalletSendCallsParams>,
    accountAddress: `0x${string}`,
  ): Promise<
    Readonly<{
      id: string;
      key: Readonly<WalletCallBundleKey>;
      operationRequestHash: `0x${string}`;
      record: WalletCallBundleStoreRecord;
    }>
  > {
    const createdAt = now();
    const publicationExpiresAt = createdAt + WALLET_CALL_BUNDLE_PUBLICATION_LEASE_SECONDS;
    if (!Number.isSafeInteger(publicationExpiresAt)) return rpcFail(INTERNAL_ERROR);
    const attempts = captured.id === undefined ? GENERATED_ID_ATTEMPTS : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const id = captured.id ?? generatedBundleId();
      const bundleKey = key(id, accountAddress);
      const requestHash = hashCapturedWalletSendCallsRequest(captured, id);
      const generation = generatedBundleId();
      const operationRequestHash = hashWalletCallBundleProvenance(requestHash, generation);
      const result = await store.reserveAccepted({
        key: bundleKey,
        grantId: input.port.grantId,
        generation,
        account: accountAddress,
        chainId: input.chain,
        createdAt,
        publicationExpiresAt,
        requestHash,
      });
      if (result.status === "committed") {
        return Object.freeze({
          id,
          key: bundleKey,
          operationRequestHash,
          record: result.record,
        });
      }
      if (captured.id !== undefined) return rpcFail(DUPLICATE_ID);
    }
    return rpcFail(INTERNAL_ERROR);
  }

  async function terminalize(
    bundleKey: Readonly<WalletCallBundleKey>,
    observed: WalletCallBundleStoreRecord,
  ): Promise<WalletCallBundleStoreRecord> {
    const result = await store.markTerminal({
      key: bundleKey,
      expectedStoreRevision: observed.storeRevision,
      expectedGeneration: observed.value.generation,
      updatedAt: Math.max(now(), observed.updatedAt),
    });
    if (result.status === "committed") return result.record;
    if (result.current !== undefined) {
      if (result.current.value.generation !== observed.value.generation) {
        return rpcFail(UNKNOWN_BUNDLE_ID);
      }
      return result.current;
    }
    return rpcFail(INTERNAL_ERROR);
  }

  function operationBinding(
    record: WalletCallBundleStoreRecord,
  ): NonNullable<WalletCallBundleStoreRecord["value"]["operation"]> | null {
    const binding = record.value.operation;
    if (binding === null) return null;
    const identity = binding.identity;
    if (
      identity.entryPoint !== kernelV4Deployment(record.value.chainId).entryPoint.address ||
      identity.requestHash !==
        hashWalletCallBundleProvenance(record.value.requestHash, record.value.generation)
    ) {
      return rpcFail(INTERNAL_ERROR);
    }
    return binding;
  }

  async function sendCalls(params: unknown): Promise<Readonly<{ id: string }>> {
    const captured = captureWalletSendCallsParams(params, input.chain);
    const capabilityEffect = applyWalletCapabilities({
      atomic: Object.freeze({ atomicRequired: captured.atomicRequired }),
      calls: captured.calls,
      chainId: input.chain,
      atomicExecution: true,
      ...(captured.capabilities === undefined ? {} : { capabilities: captured.capabilities }),
      registeredPaymasterServiceUrl: input.port.registeredPaymasterServiceUrl(input.chain),
      staticPaymasterConfigurationHash: input.port.staticPaymasterConfigurationHash(input.chain),
    });
    if (!capabilityEffect.atomic) return rpcFail(INTERNAL_ERROR);
    const accountAddress = await account();
    if (captured.from !== undefined && captured.from !== accountAddress) {
      return rpcFail(UNAUTHORIZED);
    }
    if (
      captured.id !== undefined &&
      (await store.get(key(captured.id, accountAddress))) !== undefined
    ) {
      return rpcFail(DUPLICATE_ID);
    }

    const accepted = await reserve(captured, accountAddress);
    let reservationStarted = false;
    let reserved: WalletCallBundleStoreRecord | null = null;
    let reservedPointer: OaathProviderOperationPointer | null = null;

    try {
      const calls = Object.freeze(
        capabilityEffect.calls.map((call) =>
          Object.freeze({
            target: call.to,
            value: BigInt(call.value ?? "0x0").toString(10),
            data: call.data ?? "0x",
          }),
        ),
      );
      const operation = await input.port.startCalls(
        Object.freeze({
          chain: input.chain,
          calls,
          requestHash: accepted.operationRequestHash,
          paymaster: capabilityEffect.paymaster,
        }),
        Object.freeze({
          reserve: async (exact: OaathProviderOperationPointer) => {
            const identity = exact.identity;
            if (
              identity.grantId !== input.port.grantId ||
              identity.chainId !== input.chain ||
              identity.kind !== "execution" ||
              identity.account !== accountAddress ||
              identity.entryPoint !== kernelV4Deployment(input.chain).entryPoint.address ||
              identity.requestHash !== accepted.operationRequestHash
            ) {
              return rpcFail(INTERNAL_ERROR);
            }
            reservationStarted = true;
            const result = await store.reserveOperation({
              key: accepted.key,
              expectedStoreRevision: accepted.record.storeRevision,
              expectedGeneration: accepted.record.value.generation,
              operation: Object.freeze({ identity }),
              updatedAt: now(),
            });
            if (result.status !== "committed") return rpcFail(INTERNAL_ERROR);
            reserved = result.record;
            reservedPointer = exact;
          },
          confirm: async (exact: OaathProviderOperationPointer) => {
            if (
              reserved === null ||
              reservedPointer === null ||
              !sameOperationPointer(reservedPointer, exact)
            ) {
              return rpcFail(INTERNAL_ERROR);
            }
            const result = await store.confirmOperationPublished({
              key: accepted.key,
              expectedStoreRevision: reserved.storeRevision,
              expectedGeneration: reserved.value.generation,
              updatedAt: now(),
            });
            if (result.status !== "committed") return rpcFail(INTERNAL_ERROR);
            reserved = result.record;
          },
          abandon: async (exact: OaathProviderOperationPointer) => {
            if (
              reserved === null ||
              reservedPointer === null ||
              !sameOperationPointer(reservedPointer, exact)
            ) {
              return rpcFail(INTERNAL_ERROR);
            }
            if (reserved.value.state === "terminal") return;
            const result = await store.markTerminal({
              key: accepted.key,
              expectedStoreRevision: reserved.storeRevision,
              expectedGeneration: reserved.value.generation,
              updatedAt: Math.max(now(), reserved.updatedAt),
            });
            if (result.status === "committed") {
              reserved = result.record;
              return;
            }
            if (
              result.current?.value.generation === reserved.value.generation &&
              result.current.value.state === "terminal"
            ) {
              reserved = result.current;
              return;
            }
            return rpcFail(INTERNAL_ERROR);
          },
        }),
      );
      const bound = await store.get(accepted.key);
      if (
        bound === undefined ||
        bound.value.generation !== accepted.record.value.generation ||
        bound.value.state !== "operation_bound"
      ) {
        return rpcFail(INTERNAL_ERROR);
      }
      const released = await store.releaseOperationPublication({
        key: accepted.key,
        expectedStoreRevision: bound.storeRevision,
        expectedGeneration: bound.value.generation,
        updatedAt: Math.max(now(), bound.updatedAt),
      });
      if (released.status !== "committed") return rpcFail(INTERNAL_ERROR);
      reserved = released.record;
      // Status reconstructs from durable exact identity, so this start handle
      // owns no provider authority after wallet_sendCalls returns.
      await operation.close().catch(() => undefined);
      return Object.freeze({ id: accepted.id });
    } catch (error) {
      // Before the reservation callback, the runner cannot have published, signed,
      // or submitted. The failed reservation remains terminal and cannot be
      // silently reused. Once reservation starts, preserve its uncertain state for
      // exact recovery instead of inferring that no send happened.
      if (!reservationStarted) {
        await terminalize(accepted.key, accepted.record).catch(() => undefined);
      }
      throw error;
    }
  }

  async function retainedBundle(
    bundleKey: Readonly<WalletCallBundleKey>,
  ): Promise<WalletCallBundleStoreRecord | undefined> {
    return store.get(bundleKey);
  }

  async function statusFromOperation(
    record: WalletCallBundleStoreRecord,
    bundleKey: Readonly<WalletCallBundleKey>,
  ): Promise<Readonly<Eip5792CallsStatus>> {
    const binding = operationBinding(record);
    if (binding === null) {
      return record.value.state === "terminal"
        ? offchainFailureStatus(record.value.id, record.value.chainId)
        : rpcFail(INTERNAL_ERROR);
    }
    if (
      (record.value.state === "operation_reserved" || record.value.state === "operation_bound") &&
      record.value.publicationReleasedAt === null &&
      now() < record.value.publicationExpiresAt
    ) {
      return pendingStatus(record.value.id, record.value.chainId);
    }
    let recovered = await input.port.recoverOperation(binding);
    if (recovered.status === "prepared" && now() >= record.value.publicationExpiresAt) {
      recovered = await input.port.abandonPreparedOperation(binding);
    }
    if (recovered.status === "absent") {
      // A publication CAS may still be in progress. Missing evidence never
      // authorizes resubmission. The durable lease may, however, prove the
      // pre-submission producer lost its fenced publication window.
      if (record.value.state === "terminal" && record.value.terminalFrom === "operation_reserved") {
        return offchainFailureStatus(record.value.id, record.value.chainId);
      }
      if (record.value.state !== "operation_reserved") return rpcFail(INTERNAL_ERROR);
      if (now() < record.value.publicationExpiresAt) {
        return pendingStatus(record.value.id, record.value.chainId);
      }
      const terminal = await terminalize(bundleKey, record);
      if (
        terminal.value.state !== "terminal" ||
        terminal.value.terminalFrom !== "operation_reserved"
      ) {
        return rpcFail(INTERNAL_ERROR);
      }
      return offchainFailureStatus(record.value.id, record.value.chainId);
    }
    if (recovered.status === "request_conflict") {
      if (
        record.value.state !== "operation_reserved" &&
        !(record.value.state === "terminal" && record.value.terminalFrom === "operation_reserved")
      ) {
        return rpcFail(INTERNAL_ERROR);
      }
      if (record.value.state === "operation_reserved") {
        const terminal = await terminalize(bundleKey, record);
        if (
          terminal.value.state !== "terminal" ||
          terminal.value.terminalFrom !== "operation_reserved"
        ) {
          return rpcFail(INTERNAL_ERROR);
        }
      }
      return offchainFailureStatus(record.value.id, record.value.chainId);
    }
    if (recovered.status === "abandoned") {
      if (
        record.value.state !== "operation_reserved" &&
        record.value.state !== "operation_bound" &&
        !(
          record.value.state === "terminal" &&
          (record.value.terminalFrom === "operation_reserved" ||
            record.value.terminalFrom === "operation_bound")
        )
      ) {
        return rpcFail(INTERNAL_ERROR);
      }
      if (record.value.state === "operation_reserved" || record.value.state === "operation_bound") {
        const terminal = await terminalize(bundleKey, record);
        if (
          terminal.value.state !== "terminal" ||
          terminal.value.terminalFrom !== record.value.state
        ) {
          return rpcFail(INTERNAL_ERROR);
        }
      }
      return offchainFailureStatus(record.value.id, record.value.chainId);
    }
    if (recovered.status === "prepared") {
      if (record.value.state === "terminal") return rpcFail(INTERNAL_ERROR);
      return pendingStatus(record.value.id, record.value.chainId);
    }

    if (
      record.value.state === "operation_reserved" ||
      (record.value.state === "terminal" && record.value.terminalFrom === "operation_reserved")
    ) {
      await recovered.operation.close().catch(() => undefined);
      return rpcFail(INTERNAL_ERROR);
    }

    const operation = recovered.operation;
    try {
      const outcome = await operation.observe();
      const status =
        outcome.status === "finalized"
          ? projectProviderStatus({
              id: record.value.id,
              chainId: record.value.chainId,
              outcome,
              receipt: await operation.receipt(),
            })
          : projectProviderStatus({
              id: record.value.id,
              chainId: record.value.chainId,
              outcome,
            });
      if (status.status === 100) {
        if (record.value.state === "terminal") return rpcFail(INTERNAL_ERROR);
        return status;
      }
      if (record.value.state !== "terminal") {
        const terminal = await terminalize(bundleKey, record);
        if (terminal.value.state !== "terminal") return rpcFail(INTERNAL_ERROR);
      }
      return status;
    } finally {
      await operation.close().catch(() => undefined);
    }
  }

  async function readStatus(id: string): Promise<Readonly<Eip5792CallsStatus>> {
    const bundleKey = key(id, await account());
    let record = await retainedBundle(bundleKey);
    if (record === undefined) return rpcFail(UNKNOWN_BUNDLE_ID);
    if (record.value.grantId !== input.port.grantId) return rpcFail(UNKNOWN_BUNDLE_ID);
    if (record.value.state === "accepted") {
      if (now() < record.value.publicationExpiresAt) {
        return pendingStatus(id, record.value.chainId);
      }
      record = await terminalize(bundleKey, record);
      if (record.value.state !== "terminal" || record.value.terminalFrom !== "accepted") {
        return rpcFail(INTERNAL_ERROR);
      }
    }
    if (record.value.state === "terminal" && record.value.operation === null) {
      return offchainFailureStatus(record.value.id, record.value.chainId);
    }
    return statusFromOperation(record, bundleKey);
  }

  function statusForId(id: string): Promise<Readonly<Eip5792CallsStatus>> {
    return readStatus(id);
  }

  async function getCallsStatus(params: unknown): Promise<Readonly<Eip5792CallsStatus>> {
    return statusForId(captureWalletCallsStatusParams(params));
  }

  async function showCallsStatus(params: unknown): Promise<undefined> {
    const id = captureWalletCallsStatusParams(params);
    if (presenter === undefined) return rpcFail(UNSUPPORTED_METHOD);
    await presenter(await statusForId(id));
    return undefined;
  }

  async function getCapabilities(params: unknown): Promise<Readonly<Record<string, unknown>>> {
    const captured = captureWalletGetCapabilitiesParams(params);
    const accountAddress = (await input.port.authorizedAccount(input.chain)).toLowerCase();
    if (!isWalletAddress(accountAddress)) return rpcFail(INTERNAL_ERROR);
    if (captured.address !== accountAddress) return rpcFail(UNAUTHORIZED);

    const requested = captured.chainIds ?? Object.freeze([chainId]);
    const result: Record<string, unknown> = Object.create(null);
    if (requested.includes(chainId)) {
      result[chainId] = advertiseWalletCapabilities({
        atomicExecution: true,
        paymasterService: input.port.registeredPaymasterServiceUrl(input.chain) !== null,
        staticPaymasterConfigurationHash: input.port.staticPaymasterConfigurationHash(input.chain),
      });
    }
    return Object.freeze(result);
  }

  return Object.freeze({ sendCalls, getCallsStatus, showCallsStatus, getCapabilities });
}
