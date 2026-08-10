/**
 * OAAth's explicit experimental ERC-7836 prepared-call profile.
 *
 * PreparedCallStore owns the one-use context. OperationStore owns every fact
 * after publication. The opaque RPC token carries no authority or unsigned
 * operation bytes, and a reload can only resume the exact retained digest.
 *
 * @author taek <leekt216@gmail.com>
 */
import { encodeAbiParameters, type Hash, keccak256 } from "viem";
import { OaathClientError } from "../client/errors.js";
import type {
  OaathExternalPreparedCallPlan,
  OaathGrantProviderPort,
  OaathProviderExecutionRouteAdmission,
  OaathProviderOperationPointer,
  OaathProviderOperationReservation,
  OaathProviderValidityAdmission,
  OaathValidatedPreparedCalls,
} from "../client/grant-handle.js";
import { kernelV4Deployment } from "../kernel-v4.js";
import type {
  WalletCallBundleKey,
  WalletCallBundleStoreRecord,
} from "../persistence/interfaces.js";
import { deriveOperationId } from "../prepared-user-operation.js";
import { WALLET_CALL_BUNDLE_PUBLICATION_LEASE_SECONDS } from "./bundle-store.js";
import { applyWalletCapabilities } from "./capabilities.js";
import {
  type CapturedWalletCapabilities,
  type CapturedWalletPreparedCallsKey,
  type CapturedWalletSendPreparedCallsParams,
  captureWalletPrepareCallsParams,
  captureWalletSendPreparedCallsParams,
  hashCapturedWalletPrepareCallsRequest,
  hashCapturedWalletSendPreparedCallsRequest,
  hashWalletCallBundleProvenance,
  isWalletAddress,
  OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION,
} from "./capture.js";
import {
  type OaathCallsConfirmation,
  type OaathCallsConfirmer,
  projectValidityTimeRangeConfirmation,
} from "./eip5792.js";
import {
  BUNDLE_TOO_LARGE,
  INTERNAL_ERROR,
  INVALID_PARAMS,
  rpcFail,
  UNAUTHORIZED,
  UNSUPPORTED_CAPABILITY,
  USER_REJECTED_REQUEST,
} from "./errors.js";
import {
  OAATH_PREPARED_CALL_CONTEXT_LIFETIME_SECONDS,
  type PreparedCallContextRecord,
  type PreparedCallKey,
  type PreparedCallStore,
  type PreparedCallStoreRecord,
} from "./prepared-call-store.js";
import type { OaathWalletCallResultCapabilities } from "./result-capabilities.js";

const GENERATED_ID_ATTEMPTS = 8;
const HASH = /^0x[0-9a-f]{64}$/u;
const ECHO_SIGNATURE_SENTINEL = "0x00" as const;
const UNSUPPORTED_VALIDITY_ADMISSION = Object.freeze({ status: "unsupported" as const });

export interface Erc7836Orchestrator {
  readonly prepareCalls: (params: unknown) => Promise<
    Readonly<{
      version: "1";
      chainId: `0x${string}`;
      capabilities: Readonly<Record<string, unknown>>;
      context: Readonly<{
        version: typeof OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION;
        id: Hash;
      }>;
      key: Readonly<CapturedWalletPreparedCallsKey>;
      digest: Hash;
    }>
  >;
  readonly sendPreparedCalls: (params: unknown) => Promise<
    Readonly<{
      id: string;
      capabilities?: Readonly<OaathWalletCallResultCapabilities>;
    }>
  >;
}

interface CreateErc7836OrchestratorInput {
  readonly port: Readonly<OaathGrantProviderPort>;
  readonly chain: number;
  readonly confirmCalls?: OaathCallsConfirmer;
}

function generatedHash(): Hash {
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

function sameKeyHint(
  left: Readonly<CapturedWalletPreparedCallsKey>,
  right: Readonly<CapturedWalletPreparedCallsKey>,
): boolean {
  return (
    left.type === right.type && left.publicKey === right.publicKey && left.prehash === right.prehash
  );
}

function sameOperationPointer(
  left: Readonly<OaathProviderOperationPointer>,
  right: Readonly<OaathProviderOperationPointer>,
): boolean {
  const first = left.identity;
  const second = right.identity;
  return (
    first.kind === second.kind &&
    first.grantId === second.grantId &&
    first.chainId === second.chainId &&
    first.entryPoint === second.entryPoint &&
    first.account === second.account &&
    first.nonce === second.nonce &&
    first.userOperationHash === second.userOperationHash &&
    first.requestHash === second.requestHash
  );
}

function sameResultCapabilities(
  left: Readonly<OaathWalletCallResultCapabilities> | null,
  right: Readonly<OaathWalletCallResultCapabilities> | null,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function echoedCapabilities(
  capabilities: Readonly<CapturedWalletCapabilities> | undefined,
): Readonly<Record<string, unknown>> {
  return capabilities?.values ?? Object.freeze(Object.create(null) as Record<string, unknown>);
}

function preparedBundleRequestHash(input: {
  readonly prepareRequestHash: Hash;
  readonly sendEchoHash: Hash;
}): Hash {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string", name: "domain" },
        { type: "bytes32", name: "prepareRequestHash" },
        { type: "bytes32", name: "sendEchoHash" },
      ],
      ["@oaath/sdk:erc7836-prepared-bundle/v1", input.prepareRequestHash, input.sendEchoHash],
    ),
  );
}

function sendEchoHash(input: Readonly<CapturedWalletSendPreparedCallsParams>): Hash {
  return hashCapturedWalletSendPreparedCallsRequest(
    Object.freeze({ ...input, signature: ECHO_SIGNATURE_SENTINEL }),
  );
}

function toPlan(
  record: Readonly<PreparedCallContextRecord>,
): Readonly<OaathExternalPreparedCallPlan> {
  return Object.freeze({
    grantId: record.grantId,
    account: record.account,
    chainId: record.chainId,
    calls: record.calls,
    key: record.keyHint,
    custody: record.custody,
    materialization: record.materialization,
    quote: record.quote,
    decision: record.decision,
    resultCapabilities: record.resultCapabilities,
    prepared: record.prepared,
    validityTimeRange: record.validityTimeRange,
    expiresAt: record.expiresAt,
  });
}

function mapPreparationFailure(error: unknown): never {
  if (error instanceof OaathClientError) {
    if (error.source === "operator_credential_mismatch") return rpcFail(UNAUTHORIZED);
    if (error.code === "oaath_client_capability_unsupported") {
      return rpcFail(UNSUPPORTED_CAPABILITY);
    }
  }
  throw error;
}

function mapValidationFailure(error: unknown): never {
  if (error instanceof OaathClientError) {
    if (
      error.source === "prepared_call_stale" ||
      error.code === "oaath_client_signing_failed" ||
      error.code === "oaath_client_input_invalid"
    ) {
      return rpcFail(INVALID_PARAMS);
    }
    if (error.source === "operator_credential_mismatch") return rpcFail(UNAUTHORIZED);
  }
  throw error;
}

export function createErc7836Orchestrator(
  input: Readonly<CreateErc7836OrchestratorInput>,
): Readonly<Erc7836Orchestrator> {
  const contexts: PreparedCallStore = input.port.preparedCallContexts;
  const bundles = input.port.walletCallBundles;

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

  function contextKey(contextId: Hash): Readonly<PreparedCallKey> {
    if (!HASH.test(input.port.providerScopeId)) return rpcFail(INTERNAL_ERROR);
    return Object.freeze({
      providerScopeId: input.port.providerScopeId as Hash,
      contextId,
    });
  }

  function bundleKey(record: Readonly<PreparedCallContextRecord>): Readonly<WalletCallBundleKey> {
    return Object.freeze({
      providerScopeId: record.providerScopeId,
      account: record.account,
      id: record.bundleId,
    });
  }

  async function account(): Promise<`0x${string}`> {
    const retained = (await input.port.authorizedAccount(input.chain)).toLowerCase();
    if (!isWalletAddress(retained)) return rpcFail(INTERNAL_ERROR);
    return retained;
  }

  function calls(
    capturedCalls: ReturnType<typeof captureWalletPrepareCallsParams>["calls"],
  ): readonly Readonly<{ target: `0x${string}`; value: string; data: `0x${string}` }>[] {
    return Object.freeze(
      capturedCalls.map((call) =>
        Object.freeze({
          target: call.to,
          value: BigInt(call.value ?? "0x0").toString(10),
          data: call.data ?? "0x",
        }),
      ),
    );
  }

  function expectedPointer(
    record: Readonly<PreparedCallContextRecord>,
  ): Readonly<OaathProviderOperationPointer> {
    return Object.freeze({
      identity: deriveOperationId(record.prepared, record.operationRequestHash),
    });
  }

  async function reserveBundle(
    record: Readonly<PreparedCallContextRecord & { state: "consumed" }>,
  ): Promise<WalletCallBundleStoreRecord> {
    const key = bundleKey(record);
    const retained = await bundles.get(key);
    if (retained !== undefined) {
      if (
        retained.value.generation !== record.bundleGeneration ||
        retained.value.grantId !== record.grantId ||
        retained.value.account !== record.account ||
        retained.value.chainId !== record.chainId ||
        retained.value.requestHash !== record.bundleRequestHash
      ) {
        rpcFail(INTERNAL_ERROR);
      }
      if (
        retained.value.operation !== null &&
        (!sameOperationPointer(retained.value.operation, expectedPointer(record)) ||
          !sameResultCapabilities(
            retained.value.operation.resultCapabilities,
            record.resultCapabilities,
          ))
      ) {
        rpcFail(INTERNAL_ERROR);
      }
      return retained;
    }
    const reserved = await bundles.reserveAccepted({
      key,
      grantId: record.grantId,
      generation: record.bundleGeneration,
      account: record.account,
      chainId: record.chainId,
      createdAt: record.consumedAt,
      publicationExpiresAt: record.publicationExpiresAt,
      requestHash: record.bundleRequestHash,
    });
    if (reserved.status === "committed") return reserved.record;
    if (reserved.status === "capacity_exhausted") return rpcFail(BUNDLE_TOO_LARGE);
    const current = reserved.current;
    if (
      current?.value.generation === record.bundleGeneration &&
      current.value.requestHash === record.bundleRequestHash
    ) {
      return current;
    }
    return rpcFail(INTERNAL_ERROR);
  }

  function publication(
    context: Readonly<PreparedCallContextRecord & { state: "consumed" }>,
    initial: WalletCallBundleStoreRecord,
  ): Readonly<{
    publication: Readonly<{
      reserve: (reservation: Readonly<OaathProviderOperationReservation>) => Promise<void>;
      confirm: (pointer: OaathProviderOperationPointer) => Promise<void>;
      abandon: (pointer: OaathProviderOperationPointer) => Promise<void>;
    }>;
    retained: () => WalletCallBundleStoreRecord;
  }> {
    const key = bundleKey(context);
    const exact = expectedPointer(context);
    let retained = initial;

    function requirePointer(pointer: OaathProviderOperationPointer): void {
      if (
        !sameOperationPointer(pointer, exact) ||
        pointer.identity.entryPoint !== kernelV4Deployment(input.chain).entryPoint.address
      ) {
        rpcFail(INTERNAL_ERROR);
      }
    }

    return Object.freeze({
      publication: Object.freeze({
        reserve: async (reservation: Readonly<OaathProviderOperationReservation>) => {
          const pointer = reservation.operation;
          if (!sameResultCapabilities(reservation.resultCapabilities, context.resultCapabilities)) {
            return rpcFail(INTERNAL_ERROR);
          }
          requirePointer(pointer);
          retained = (await bundles.get(key)) ?? retained;
          if (retained.value.operation !== null) {
            if (
              !sameOperationPointer(retained.value.operation, exact) ||
              !sameResultCapabilities(
                retained.value.operation.resultCapabilities,
                context.resultCapabilities,
              )
            )
              return rpcFail(INTERNAL_ERROR);
            return;
          }
          const result = await bundles.reserveOperation({
            key,
            expectedStoreRevision: retained.storeRevision,
            expectedGeneration: context.bundleGeneration,
            operation: Object.freeze({
              identity: exact.identity,
              resultCapabilities: context.resultCapabilities,
            }),
            updatedAt: Math.max(now(), retained.updatedAt),
          });
          if (result.status === "committed") {
            retained = result.record;
            return;
          }
          if (
            result.current?.value.operation !== null &&
            result.current?.value.operation !== undefined &&
            sameOperationPointer(result.current.value.operation, exact) &&
            sameResultCapabilities(
              result.current.value.operation.resultCapabilities,
              context.resultCapabilities,
            )
          ) {
            retained = result.current;
            return;
          }
          return rpcFail(INTERNAL_ERROR);
        },
        confirm: async (pointer: OaathProviderOperationPointer) => {
          requirePointer(pointer);
          retained = (await bundles.get(key)) ?? retained;
          if (retained.value.state === "operation_bound") return;
          if (retained.value.state !== "operation_reserved") return rpcFail(INTERNAL_ERROR);
          const result = await bundles.confirmOperationPublished({
            key,
            expectedStoreRevision: retained.storeRevision,
            expectedGeneration: context.bundleGeneration,
            updatedAt: Math.max(now(), retained.updatedAt),
          });
          if (result.status === "committed") {
            retained = result.record;
            return;
          }
          if (result.current?.value.state === "operation_bound") {
            retained = result.current;
            return;
          }
          return rpcFail(INTERNAL_ERROR);
        },
        abandon: async (pointer: OaathProviderOperationPointer) => {
          requirePointer(pointer);
          retained = (await bundles.get(key)) ?? retained;
          if (retained.value.state === "terminal") return;
          const result = await bundles.markTerminal({
            key,
            expectedStoreRevision: retained.storeRevision,
            expectedGeneration: context.bundleGeneration,
            updatedAt: Math.max(now(), retained.updatedAt),
          });
          if (result.status === "committed") {
            retained = result.record;
            return;
          }
          if (result.current?.value.state === "terminal") {
            retained = result.current;
            return;
          }
          return rpcFail(INTERNAL_ERROR);
        },
      }),
      retained: () => retained,
    });
  }

  async function releasePublication(
    record: Readonly<PreparedCallContextRecord & { state: "consumed" }>,
    retainedValue: WalletCallBundleStoreRecord,
  ): Promise<void> {
    let retained = (await bundles.get(bundleKey(record))) ?? retainedValue;
    if (
      retained.value.operation === null ||
      !sameOperationPointer(retained.value.operation, expectedPointer(record)) ||
      !sameResultCapabilities(
        retained.value.operation.resultCapabilities,
        record.resultCapabilities,
      )
    ) {
      rpcFail(INTERNAL_ERROR);
    }
    if (retained.value.publicationReleasedAt !== null) return;
    if (retained.value.state !== "operation_bound") return rpcFail(INTERNAL_ERROR);
    const released = await bundles.releaseOperationPublication({
      key: bundleKey(record),
      expectedStoreRevision: retained.storeRevision,
      expectedGeneration: record.bundleGeneration,
      updatedAt: Math.max(now(), retained.updatedAt),
    });
    if (released.status === "committed") return;
    retained = released.current ?? retained;
    if (retained.value.publicationReleasedAt !== null) return;
    return rpcFail(INTERNAL_ERROR);
  }

  async function prepareCalls(params: unknown) {
    const captured = captureWalletPrepareCallsParams(params, input.chain);
    const capabilityEffect = applyWalletCapabilities({
      atomic: Object.freeze({ atomicRequired: true }),
      calls: captured.calls,
      chainId: input.chain,
      atomicExecution: true,
      ...(captured.capabilities === undefined ? {} : { capabilities: captured.capabilities }),
      registeredPaymasterServiceUrl: input.port.registeredPaymasterServiceUrl(input.chain),
      staticPaymasterConfigurationHash: input.port.staticPaymasterConfigurationHash(input.chain),
    });
    if (!capabilityEffect.atomic) return rpcFail(INTERNAL_ERROR);
    if (capabilityEffect.paymaster?.kind === "erc7902-static") {
      return rpcFail(INTERNAL_ERROR);
    }
    const accountAddress = await account();
    if (captured.from !== undefined && captured.from !== accountAddress) {
      return rpcFail(UNAUTHORIZED);
    }
    let paymaster = capabilityEffect.paymaster;
    let executionRouteAdmission: Readonly<OaathProviderExecutionRouteAdmission> | null = null;
    if (paymaster !== null) {
      const admitted = await input.port.admitExecutionRoute(input.chain);
      executionRouteAdmission = admitted.admission;
      if (admitted.sponsorship === "unsupported") {
        if (captured.capabilities?.paymasterService?.optional !== true) {
          return rpcFail(UNSUPPORTED_CAPABILITY);
        }
        paymaster = null;
      }
    }
    const preparedCalls = calls(capabilityEffect.calls);
    const requestedValidity = capabilityEffect.validityTimeRange;
    if (requestedValidity !== null && input.confirmCalls === undefined) {
      if (!requestedValidity.optional) return rpcFail(UNSUPPORTED_CAPABILITY);
    }
    let validityAdmission: Readonly<OaathProviderValidityAdmission> | null = null;
    if (requestedValidity !== null && input.confirmCalls !== undefined) {
      const admitted = await input.port
        .admitValidityTimeRange({
          chain: input.chain,
          range: Object.freeze({
            validAfter: requestedValidity.validAfter,
            validUntil: requestedValidity.validUntil,
          }),
        })
        .catch(() => UNSUPPORTED_VALIDITY_ADMISSION);
      const presentedValidity =
        admitted.status === "accepted"
          ? projectValidityTimeRangeConfirmation(requestedValidity)
          : null;
      if (admitted.status === "accepted" && presentedValidity !== null) {
        validityAdmission = admitted.admission;
        let decision: unknown;
        try {
          decision = await input.confirmCalls(
            Object.freeze({
              account: accountAddress,
              chainId: captured.chainId,
              calls: preparedCalls,
              validityTimeRange: presentedValidity,
            } satisfies OaathCallsConfirmation),
          );
        } catch {
          return rpcFail(INTERNAL_ERROR);
        }
        if (decision !== "approved") {
          if (decision === "rejected") return rpcFail(USER_REJECTED_REQUEST);
          return rpcFail(INTERNAL_ERROR);
        }
      } else if (!requestedValidity.optional) {
        return rpcFail(UNSUPPORTED_CAPABILITY);
      }
    }
    const plan = await input.port
      .prepareCalls({
        chain: input.chain,
        calls: preparedCalls,
        key: captured.key,
        paymaster,
        ...(validityAdmission === null ? {} : { validityAdmission }),
        ...(executionRouteAdmission === null ? {} : { executionRouteAdmission }),
      })
      .catch(mapPreparationFailure);
    const createdAt = now();
    const validityExpiresAt =
      plan.validityTimeRange === null
        ? plan.expiresAt
        : Number(BigInt(plan.validityTimeRange.validUntil) + 1n);
    const expiresAt = Math.min(
      createdAt + OAATH_PREPARED_CALL_CONTEXT_LIFETIME_SECONDS,
      plan.expiresAt,
      validityExpiresAt,
    );
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= createdAt) return rpcFail(UNAUTHORIZED);
    const prepareRequestHash = hashCapturedWalletPrepareCallsRequest(captured);
    const capabilities = echoedCapabilities(captured.capabilities);

    for (let attempt = 0; attempt < GENERATED_ID_ATTEMPTS; attempt += 1) {
      const contextId = generatedHash();
      const bundleId = generatedHash();
      const bundleGeneration = generatedHash();
      const context = Object.freeze({
        version: OAATH_PREPARED_CALL_CONTEXT_TOKEN_VERSION,
        id: contextId,
      });
      const echo = Object.freeze({
        version: "1" as const,
        chainId: captured.chainId,
        capabilities:
          captured.capabilities ??
          Object.freeze({
            values: capabilities as Readonly<Record<string, never>>,
            ignored: Object.freeze([]),
          }),
        context,
        key: captured.key,
        signature: ECHO_SIGNATURE_SENTINEL,
      });
      const bundleRequestHash = preparedBundleRequestHash({
        prepareRequestHash,
        sendEchoHash: sendEchoHash(echo),
      });
      const operationRequestHash = hashWalletCallBundleProvenance(
        bundleRequestHash,
        bundleGeneration,
      );
      const reserved = await contexts.reservePrepared({
        key: contextKey(contextId),
        grantId: plan.grantId,
        account: plan.account,
        chainId: plan.chainId,
        createdAt,
        expiresAt,
        validityTimeRange: plan.validityTimeRange,
        requestHash: prepareRequestHash,
        keyHint: plan.key,
        custody: plan.custody,
        materialization: plan.materialization,
        quote: plan.quote,
        decision: plan.decision,
        resultCapabilities: plan.resultCapabilities,
        calls: plan.calls,
        prepared: plan.prepared,
        digest: plan.prepared.userOperationHash,
        bundleId,
        bundleGeneration,
        bundleRequestHash,
        operationRequestHash,
      });
      if (reserved.status !== "committed") continue;
      return Object.freeze({
        version: "1" as const,
        chainId: captured.chainId,
        capabilities,
        context,
        key: captured.key,
        digest: plan.prepared.userOperationHash,
      });
    }
    return rpcFail(INTERNAL_ERROR);
  }

  function sendResult(record: Readonly<PreparedCallContextRecord>): Readonly<{
    id: string;
    capabilities?: Readonly<OaathWalletCallResultCapabilities>;
  }> {
    return Object.freeze({
      id: record.bundleId,
      ...(record.resultCapabilities === null ? {} : { capabilities: record.resultCapabilities }),
    });
  }

  async function sendPreparedCalls(params: unknown): Promise<
    Readonly<{
      id: string;
      capabilities?: Readonly<OaathWalletCallResultCapabilities>;
    }>
  > {
    const captured = captureWalletSendPreparedCallsParams(params, input.chain);
    const key = contextKey(captured.context.id);
    let retained: PreparedCallStoreRecord | undefined = await contexts.get(key);
    if (retained === undefined) return rpcFail(UNAUTHORIZED);
    if (!sameKeyHint(captured.key, retained.value.keyHint)) return rpcFail(UNAUTHORIZED);
    const expectedBundleRequestHash = preparedBundleRequestHash({
      prepareRequestHash: retained.value.requestHash,
      sendEchoHash: sendEchoHash(captured),
    });
    if (expectedBundleRequestHash !== retained.value.bundleRequestHash) {
      return rpcFail(INVALID_PARAMS);
    }
    if (retained.value.state === "expired" || retained.value.state === "invalidated_as_stale") {
      return rpcFail(INVALID_PARAMS);
    }
    const at = now();
    if (retained.value.state === "prepared" && at >= retained.value.expiresAt) {
      const expired = await contexts.markExpired({
        key,
        expectedStoreRevision: retained.storeRevision,
        terminalAt: at,
      });
      retained = expired.status === "committed" ? expired.record : expired.current;
      return rpcFail(INVALID_PARAMS);
    }

    const exact = expectedPointer(retained.value);
    if (retained.value.state === "consumed") {
      const recovery = await input.port.recoverOperation(exact);
      if (recovery.status === "observable") {
        const bundle = await reserveBundle(retained.value);
        await releasePublication(retained.value, bundle);
        await recovery.operation.close().catch(() => undefined);
        return sendResult(retained.value);
      }
      if (recovery.status === "request_conflict" || recovery.status === "abandoned") {
        return rpcFail(INVALID_PARAMS);
      }
    }

    let validated: Readonly<OaathValidatedPreparedCalls>;
    try {
      validated = await input.port.validatePreparedCalls({
        plan: toPlan(retained.value),
        signature: captured.signature,
      });
    } catch (error) {
      if (retained.value.state === "prepared" && error instanceof OaathClientError) {
        if (error.source === "prepared_call_stale") {
          await contexts
            .markStale({
              key,
              expectedStoreRevision: retained.storeRevision,
              terminalAt: Math.max(at, retained.updatedAt),
            })
            .catch(() => undefined);
        }
      }
      return mapValidationFailure(error);
    }

    if (retained.value.state === "prepared") {
      const publicationExpiresAt = at + WALLET_CALL_BUNDLE_PUBLICATION_LEASE_SECONDS;
      if (!Number.isSafeInteger(publicationExpiresAt)) return rpcFail(INTERNAL_ERROR);
      const consumed = await contexts.consume({
        key,
        expectedStoreRevision: retained.storeRevision,
        consumedAt: at,
        publicationExpiresAt,
      });
      if (consumed.status === "committed") retained = consumed.record;
      else if (consumed.current?.value.state === "consumed") retained = consumed.current;
      else return rpcFail(INVALID_PARAMS);
    }
    if (retained.value.state !== "consumed") return rpcFail(INTERNAL_ERROR);

    const bundle = await reserveBundle(retained.value);
    const callbacks = publication(retained.value, bundle);
    const operation = await input.port.startPreparedCalls(
      validated,
      retained.value.operationRequestHash,
      callbacks.publication,
    );
    // A concurrent exact runner may observe the Operation after another
    // producer advanced it and therefore need no preparation callbacks of its
    // own. Idempotently converge the public bundle binding before release.
    const exactPointer = expectedPointer(retained.value);
    await callbacks.publication.reserve(
      Object.freeze({
        operation: exactPointer,
        resultCapabilities: retained.value.resultCapabilities,
      }),
    );
    await callbacks.publication.confirm(exactPointer);
    await releasePublication(retained.value, callbacks.retained());
    await operation.close().catch(() => undefined);
    return sendResult(retained.value);
  }

  return Object.freeze({ prepareCalls, sendPreparedCalls });
}
