/**
 * The application-facing handle for one active Grant.
 *
 * Authority state is not owned here: `@oaath/protocol` owns the Grant aggregate
 * and its transitions, `GrantStore` owns durability, and this handle only reads
 * the current record and composes the runtime path for one request:
 *
 * ```text
 * sendCalls  capability diagnosis
 *            -> session coverage from the approved policy
 *            -> scope denial unless conclusively covered (before probe, quote,
 *               journal, signature, and send; never an owner fallback)
 *            -> bundler probe
 *            -> decideExecution (pre-sign; no key, no prepared operation)
 *            -> createKernelRuntime for the session authority
 *            -> prepareOperation through the runner (durable before any send)
 *            -> the caller-supplied submission capability
 *            -> observation
 * ```
 *
 * Default `sendCalls` composes session authority and denies uncovered or
 * unreadable scope. Explicit `signer: "auto"` prefers an available owner for
 * the atomic call bundle before execution begins. Root authority has no Grant
 * policy envelope; its review states that distinction. Failures never select
 * another signer or authorize another submission.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  advanceGrant,
  type CaptureContext,
  type ChainBinding,
  type ChainPermissionEvidence,
  captureDenseArray,
  captureRecord,
  evaluateGrantPolicyCoverage,
  exactCapturedRecord,
  type FinalizedOperation,
  type Grant,
  type GrantPolicy,
  type GrantPolicyCoverageResult,
  type GrantState,
  type GrantTransition,
  OAATH_ISSUER_VERSION,
  type OperationIdentity,
  type OperationKind,
  type PermissionRequest,
  parseIssuerIdentity,
  parseOperationIdentity,
} from "@oaath/protocol";
import { publicKeyToAddress } from "viem/accounts";
import {
  diagnoseKernelCapability,
  type KernelCapability,
  kernelKeyCapability,
} from "../kernel/capabilities.js";
import type { KernelV33ReadRequest } from "../kernel/deployment/v33.js";
import { captureKernelGasPolicy, type KernelGasPolicy } from "../kernel/gas-policy.js";
import { credentialKeyIsReadOnly } from "../kernel/key/credential.js";
import { ownerOperator } from "../kernel/operator/owner.js";
import { sessionOperator } from "../kernel/operator/session.js";
import {
  type KernelGrantApproval,
  kernelGrantApprovalNonce,
} from "../kernel/permission/approval.js";
import { observeKernelPermissionRevocation } from "../kernel/permission/observe-revocation.js";
import { deriveSessionPolicyProfiles } from "../kernel/permission/profiles.js";
import { OAATH_KERNEL_V33_APPROVAL_VERSION } from "../kernel/permission/v33.js";
import {
  kernelV33PermissionRevocationCalls,
  kernelV33PermissionStatus,
  parseKernelV33PermissionState,
} from "../kernel/permission/v33-revocation.js";
import type { KernelRuntime, KernelRuntimeValidationMode, KeyProfile } from "../kernel/types.js";
import {
  encodeKernelV4PermissionUninstallCalls,
  type KernelV4AccountReadRequest,
  type KernelV4Call,
  type KernelV4UserOperationGas,
  type KernelV4ValidityTimeRange,
  kernelV4Deployment,
} from "../kernel-v4.js";
import {
  createOperationObserver,
  type OperationObserver,
  type OperationObserverCapabilities,
} from "../operation-observer.js";
import {
  createOperationRunner,
  type OperationObserveResult,
  type OperationRunResult,
  type OperationStartResult,
  type OperationSubmissionSession,
} from "../operation-runner.js";
import {
  deriveOperationId,
  type PreparedPaymaster,
  type PreparedUserOperation,
} from "../prepared-user-operation.js";
import type { WalletCallBundleStore } from "../provider/bundle-store.js";
import {
  type Erc7677GasEstimator,
  type Erc7677RegisteredPaymasterService,
  readCompletedErc7677ResultCapabilities,
} from "../provider/erc7677.js";
import {
  captureErc7902StaticPaymasterConfiguration,
  hashCapturedErc7902PreparedPaymaster,
} from "../provider/erc7902.js";
import type { PreparedCallStore } from "../provider/prepared-call-store.js";
import type { OaathWalletCallResultCapabilities } from "../provider/result-capabilities.js";
import { selectAutoSigner } from "../routing/auto.js";
import { type OaathBundlerProbeCapability, probeBundlerCapability } from "../routing/bundler.js";
import {
  feePayerDescriptor,
  type OaathBundlerCapability,
  type OaathSessionCoverage,
} from "../routing/capabilities.js";
import { decideExecution, supportsBundlerSponsorship } from "../routing/decide.js";
import {
  type OaathKernelSponsorshipCapability,
  prepareSponsoredKernelOperation,
} from "../routing/sponsorship.js";
import type {
  OaathExecutionDecision,
  OaathExecutionRoute,
  OaathExecutionSigner,
  OaathFeePayerDescriptor,
} from "../routing/types.js";
import {
  type GrantStore,
  type GrantStoreRecord,
  OperationStore,
  type OperationStoreAdapter,
  type OperationStoreKey,
  type OperationStoreRecord,
} from "../store.js";
import type { OaathBinding } from "./binding.js";
import {
  type ConnectedEoa,
  captureConnectedEoa,
  connectedEoaReview,
  type OaathConnectedEoaFallbackReview,
  type OaathConnectedEoaFeePayer,
  withConnectedEoaFallback,
} from "./connected-eoa.js";
import {
  clientCapability,
  clientFail,
  exactClientRecord,
  mapClientFailure,
  OaathClientError,
} from "./errors.js";
import {
  createGrantKernelRuntime,
  type GrantKernelAccount,
  type GrantKernelExecution,
  type GrantKernelPrepareInput,
  type GrantKernelRuntime,
} from "./grant-runtime.js";
import {
  createOperationHandle,
  type OaathOperationHandle,
  operationOutcome,
} from "./operation-handle.js";
import {
  capturePaymasterService,
  capturePlainCalls,
  type OaathPaymasterServiceInput,
} from "./sponsorship.js";

const SUBMISSION_TIMEOUT_MS = 30_000;
const MAX_CALLS = 64;
const USER_OPERATION_HASH = /^0x[0-9a-f]{64}$/u;
const PROVIDER_ACCOUNT = /^0x[0-9a-f]{40}$/u;
const DECIMAL_UINT48 = /^(?:0|[1-9][0-9]{0,14})$/u;
const MAX_UINT48 = (1n << 48n) - 1n;

export type OaathProviderOperationPointer = Readonly<{
  identity: Readonly<OperationIdentity>;
}>;

export interface OaathProviderOperationReservation {
  readonly operation: OaathProviderOperationPointer;
  readonly resultCapabilities: Readonly<OaathWalletCallResultCapabilities> | null;
}

export interface OaathProviderOperationPublication {
  readonly reserve: (reservation: Readonly<OaathProviderOperationReservation>) => Promise<void>;
  readonly confirm: (operation: OaathProviderOperationPointer) => Promise<void>;
  readonly abandon: (operation: OaathProviderOperationPointer) => Promise<void>;
}

/**
 * One handle-local, one-use proof that the requested range is enforceable by
 * the exact OAAth validity policy on the action chain. Structural lookalikes
 * carry no authority; the issuing Grant port retains the only membership map.
 */
export interface OaathProviderValidityAdmission {
  readonly kind: "oaath_provider_validity_admission";
}

export type OaathProviderValidityAdmissionResult =
  | Readonly<{ status: "accepted"; admission: Readonly<OaathProviderValidityAdmission> }>
  | Readonly<{ status: "unsupported" }>;

/** One handle-local, one-use classified execution-route fact. */
export interface OaathProviderExecutionRouteAdmission {
  readonly kind: "oaath_provider_execution_route_admission";
}

export type OaathProviderExecutionRouteAdmissionResult = Readonly<{
  readonly sponsorship: "supported" | "unsupported";
  readonly admission: Readonly<OaathProviderExecutionRouteAdmission>;
}>;

/** Read-only proof result used only to project current provider support. */
export type OaathProviderValidityTimeRangeSupportResult =
  | Readonly<{ status: "supported" }>
  | Readonly<{ status: "unsupported" }>;

function sameProviderOperationPointer(
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

const GRANT_PROVIDER_PORTS = new WeakMap<object, Readonly<OaathGrantProviderPort>>();

export interface OaathCallInput {
  readonly target: `0x${string}`;
  /** Canonical decimal native value; `"0"` for a plain call. */
  readonly value: string;
  readonly data: `0x${string}`;
}

export interface OaathSendCallsInput {
  /** Explicitly prefer available owner authority for this one atomic UserOperation. */
  readonly signer?: "session" | "auto";
  readonly feePayer?: Readonly<OaathConnectedEoaFeePayer>;
  readonly paymasterService?: Readonly<OaathPaymasterServiceInput>;
  readonly chain: number;
  readonly calls: readonly Readonly<OaathCallInput>[];
}

export interface OaathGetOperationInput {
  readonly chain: number;
  /** The stable ID returned by an operation handle. */
  readonly id: `0x${string}`;
}

/** OAAth's explicit experimental ERC-7836 external-key profile. */
export interface OaathExternalPreparedCallKey {
  readonly type: "secp256k1" | "webauthn-p256";
  readonly publicKey: `0x${string}`;
  readonly prehash: false;
}

/** Ephemeral provider selection; only the final prepared paymaster is durable. */
export type OaathExternalPreparedCallPaymasterSelection = Readonly<{
  readonly kind: "erc7677";
  readonly url: string;
  readonly context: unknown;
}> | null;

/** Exact preparation facts persisted by the prepared-call context owner. */
export interface OaathExternalPreparedCallPlan {
  readonly grantId: string;
  readonly account: `0x${string}`;
  readonly chainId: number;
  readonly calls: readonly Readonly<OaathCallInput>[];
  readonly key: Readonly<OaathExternalPreparedCallKey>;
  readonly custody: Readonly<{
    mode: "frontend" | "application_backend";
    providerId: string | null;
  }>;
  readonly materialization: Readonly<{
    mode: "standard" | "enable-replayable";
    permissionId: `0x${string}`;
  }>;
  readonly quote: Readonly<{ nonceKey: string; sequence: string }>;
  readonly decision: Readonly<{
    route: "bundler" | "direct";
    feePayer: Readonly<OaathFeePayerDescriptor> | null;
  }>;
  readonly resultCapabilities: Readonly<OaathWalletCallResultCapabilities> | null;
  readonly prepared: Readonly<PreparedUserOperation>;
  /** Exact applied request range, or null when preparation retained the Grant ceiling. */
  readonly validityTimeRange: Readonly<KernelV4ValidityTimeRange> | null;
  /** Exclusive bound imposed by the Grant owner or the shorter context lifetime. */
  readonly expiresAt: number;
}

/** An in-memory, locally verified capability; its signature is never persisted. */
export interface OaathValidatedPreparedCalls {
  readonly plan: Readonly<OaathExternalPreparedCallPlan>;
}

/** The exact snapshot a submission transport receives. It replaces nothing. */
export interface OaathSubmissionRequest {
  readonly prepared: Readonly<PreparedUserOperation>;
  readonly signature: `0x${string}`;
  readonly route: OaathExecutionRoute;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
}

/**
 * The caller-supplied send boundary. `open` binds the exact snapshot into a
 * zero-argument session; the SDK persists `submission_attempted` before the
 * session is opened and never opens a second one for the same identity.
 */
export interface OaathSubmissionCapability {
  readonly open: (request: Readonly<OaathSubmissionRequest>) => Promise<unknown>;
}

export interface OaathQuoteRequest {
  /**
   * `estimate`: read nonce/fees and estimate gas; `sponsorship`: read nonce/fees
   * only (ERC-7677 estimates after obtaining its stub); `revalidate`: read nonce
   * only and preserve the simulation's retained gas/fees and paymaster bytes.
   */
  readonly purpose: "estimate" | "sponsorship" | "revalidate";
  readonly chainId: number;
  readonly kind: OperationKind;
  readonly signer: OaathExecutionSigner;
  readonly account: `0x${string}`;
  /** Selected by the runtime before quoting; neither field is a quote result. */
  readonly mode: KernelRuntimeValidationMode;
  readonly validation: KernelRuntime["validation"];
  readonly calls: readonly Readonly<KernelV4Call>[];
  /** Exact static sponsorship selected before quoting, or null. */
  readonly paymaster: Readonly<PreparedPaymaster> | null;
  /**
   * Runtime-owned estimation shape. Nonce namespace and sequence start at zero;
   * gas and fees start at zero except the runtime's applicable enable floor,
   * or retain their exact prepared values when purpose is `revalidate`.
   * The quote port reads the actual nonce and fees before estimating. This
   * snapshot is never journaled, signed, or submitted. The simulation signature
   * includes any retained owner enable approval; never log or retain it.
   */
  readonly simulation: Readonly<{
    prepared: Readonly<PreparedUserOperation>;
    signature: `0x${string}`;
  }>;
}

/** Exact runtime and policy identity needed to read finalized onchain usage. */
export interface OaathUsageRequest {
  readonly grantId: string;
  readonly chainId: number;
  readonly account: `0x${string}`;
  readonly permissionId: `0x${string}`;
  readonly maximumOperations: string;
}

/**
 * The deployment chooses a uint16 nonce namespace, then reads EntryPoint's
 * sequence for encodeKernelV4NonceKey({ mode, validation, nonceKey }). Return
 * that namespace and sequence with gas; never assume the root nonce applies
 * to a session or that enable and standard validation share a sequence.
 */
export interface OaathQuoteCapability {
  readonly quote: (request: Readonly<OaathQuoteRequest>) => Promise<unknown>;
}

/**
 * One deployment-owned ERC-7677 service and bundler estimator. These are
 * explicit external-service capabilities: the deployment must hard-bound
 * their time and request budget and must not retry. OAAth invokes each stage
 * at most once for one preparation.
 */
export interface OaathRegisteredPaymasterService {
  readonly url: string;
  readonly request: Erc7677RegisteredPaymasterService["request"];
  readonly estimate: Erc7677GasEstimator["estimate"];
}

export interface OaathChainCapability {
  readonly gas?: Readonly<KernelGasPolicy>;
  readonly chainId: number;
  readonly reads: {
    readonly read: (request: KernelV4AccountReadRequest | KernelV33ReadRequest) => Promise<unknown>;
  };
  readonly observation: OperationObserverCapabilities;
  readonly bundler: OaathBundlerProbeCapability;
  readonly submission: OaathSubmissionCapability;
  readonly quote: OaathQuoteCapability["quote"];
  /**
   * Finalized per-chain usage evidence for policy coverage, or `null` when the
   * deployment provides none. Absent evidence is inconclusive, never "unused".
   */
  readonly usage: ((request: Readonly<OaathUsageRequest>) => Promise<unknown>) | null;
  readonly feePayer: Readonly<OaathFeePayerDescriptor> | null;
  /** Null means this chain does not advertise ERC-7677. */
  readonly paymasterService: Readonly<OaathRegisteredPaymasterService> | null;
  /** Authenticated commitment to one exact ERC-7902 static paymaster, or null. */
  readonly staticPaymasterConfigurationHash: `0x${string}` | null;
}

/** Records service admission invalidation; it does not invalidate an onchain signature. */
export interface OaathCapabilityInvalidationCapability {
  readonly invalidateCapability: (
    request: Readonly<{ grantId: string; capabilityHash: `0x${string}` }>,
  ) => Promise<unknown>;
}

/** Requests durable phone custody through the service; it never proves onchain completion. */
export interface OaathOwnerRevocationCapability {
  readonly request: (input: Readonly<{ grantId: string; chainId: number }>) => Promise<void>;
}

export interface OaathGrantHandle {
  readonly state: GrantState;
  readonly expiresAt: number;
  /**
   * The Grant's smart account address on one supported chain. It is derived
   * from the owner's initial packages through the chain's own factory reads —
   * never asserted — and CREATE2 makes it the same address on every supported
   * chain. Public identity only: holding it authorizes nothing.
   */
  readonly account: (chain: unknown) => Promise<`0x${string}`>;
  /** Read-only execution facts; does not reserve a nonce, authorize, sign, or submit. */
  readonly reviewCalls: (input: unknown) => Promise<Readonly<OaathCallsReview>>;
  /** Starts new calls; an unresolved operation on this chain is a state conflict. */
  readonly sendCalls: (input: unknown) => Promise<Readonly<OaathOperationHandle>>;
  /**
   * Recovers an exact execution from this Grant's local history, even after
   * expiry or revocation. Reads only; null means no matching retained record.
   */
  readonly getOperation: (input: unknown) => Promise<Readonly<OaathOperationHandle> | null>;
  /**
   * Starts or retries configured-chain revocation. May resolve while pending;
   * state becomes revoked only after every recorded chain has finalized proof.
   */
  readonly revoke: () => Promise<void>;
  readonly close: () => Promise<void>;
}

/** Current execution facts for exact calls, not a durable authorization or reservation. */
interface OaathCallsReviewBase {
  readonly fallback: Readonly<OaathConnectedEoaFallbackReview> | null;
  readonly paymasterService: Readonly<{ url: string }> | null;
  /** Applicable first-operation floor; null once installed or when no floor is configured. */
  readonly enableVerificationGasFloor: string | null;
  readonly grantId: string;
  readonly chainId: number;
  readonly accountId: string;
  readonly account: `0x${string}`;
  readonly calls: readonly Readonly<OaathCallInput>[];
  readonly route: "bundler" | "entrypoint-handleops";
  /** Structured route facts, including an unreadable bundler that forbids fallback. */
  readonly reasons: OaathExecutionDecision["reasons"];
  /** The Grant lifetime is always checked by this client. */
  readonly expiresAt: number;
}
export type OaathCallsReview = OaathCallsReviewBase &
  (
    | Readonly<{
        signer: "session";
        enforcement: Readonly<{ calls: "onchain"; expiry: "onchain"; operationCount: "onchain" }>;
        validAfter: number;
        validUntil: number;
        perChainOperationLimit: number;
      }>
    | Readonly<{
        signer: "owner";
        enforcement: Readonly<{ calls: "none"; expiry: "client"; operationCount: "none" }>;
        validAfter: null;
        validUntil: null;
        perChainOperationLimit: null;
      }>
  );

/** Internal provider capability. It is deliberately absent from the package root. */
export interface OaathGrantProviderPort {
  readonly providerScopeId: string;
  readonly grantId: string;
  readonly walletCallBundles: WalletCallBundleStore;
  readonly preparedCallContexts: PreparedCallStore;
  readonly now: () => number;
  readonly account: OaathGrantHandle["account"];
  readonly authorizedAccount: OaathGrantHandle["account"];
  readonly registeredPaymasterServiceUrl: (chain: number) => string | null;
  readonly staticPaymasterConfigurationHash: (chain: number) => `0x${string}` | null;
  readonly admitExecutionRoute: (
    chain: number,
  ) => Promise<Readonly<OaathProviderExecutionRouteAdmissionResult>>;
  readonly probeValidityTimeRangeSupport: (
    chain: number,
  ) => Promise<Readonly<OaathProviderValidityTimeRangeSupportResult>>;
  readonly admitValidityTimeRange: (
    input: Readonly<{
      chain: number;
      range: Readonly<KernelV4ValidityTimeRange>;
    }>,
  ) => Promise<Readonly<OaathProviderValidityAdmissionResult>>;
  readonly startCalls: (
    input: unknown,
    publication: OaathProviderOperationPublication,
  ) => Promise<Readonly<OaathOperationHandle>>;
  readonly prepareCalls: (
    input: Readonly<{
      chain: number;
      calls: readonly Readonly<OaathCallInput>[];
      key: Readonly<OaathExternalPreparedCallKey>;
      paymaster: OaathExternalPreparedCallPaymasterSelection;
      validityAdmission?: Readonly<OaathProviderValidityAdmission>;
      executionRouteAdmission?: Readonly<OaathProviderExecutionRouteAdmission>;
    }>,
  ) => Promise<Readonly<OaathExternalPreparedCallPlan>>;
  readonly validatePreparedCalls: (
    input: Readonly<{
      plan: Readonly<OaathExternalPreparedCallPlan>;
      signature: `0x${string}`;
    }>,
  ) => Promise<Readonly<OaathValidatedPreparedCalls>>;
  readonly startPreparedCalls: (
    validated: Readonly<OaathValidatedPreparedCalls>,
    requestHash: `0x${string}`,
    publication: OaathProviderOperationPublication,
  ) => Promise<Readonly<OaathOperationHandle>>;
  readonly recoverOperation: (input: unknown) => Promise<Readonly<OaathProviderOperationRecovery>>;
  readonly abandonPreparedOperation: (
    input: unknown,
  ) => Promise<Readonly<OaathProviderOperationRecovery>>;
}

export type OaathProviderOperationRecovery =
  | Readonly<{ status: "absent" }>
  | Readonly<{ status: "abandoned" }>
  | Readonly<{ status: "prepared" }>
  | Readonly<{ status: "request_conflict" }>
  | Readonly<{ status: "observable"; operation: Readonly<OaathOperationHandle> }>;

/** Resolves only handles minted by this module; structural lookalikes authorize nothing. */
export function grantProviderPort(handle: unknown): Readonly<OaathGrantProviderPort> {
  if (handle === null || typeof handle !== "object") {
    return clientFail("oaath_client_capability_invalid", "Grant handle is not genuine");
  }
  const port = GRANT_PROVIDER_PORTS.get(handle);
  if (!port) return clientFail("oaath_client_capability_invalid", "Grant handle is not genuine");
  return port;
}

export interface CreateGrantHandleInput {
  readonly binding: Readonly<OaathBinding>;
  readonly request: Readonly<PermissionRequest>;
  readonly approvedPolicy: Readonly<GrantPolicy>;
  /**
   * The owner's replayable install approval the decision's capabilityHash
   * binds, or null for a Grant persisted before approvals carried one. The
   * first covered execution on a chain spends it in enable-replayable mode;
   * without it no unmaterialized chain can execute.
   */
  readonly installApproval: Readonly<KernelGrantApproval> | null;
  readonly record: GrantStoreRecord;
  readonly grants: GrantStore;
  readonly operations: OperationStoreAdapter;
  readonly walletCallBundles: WalletCallBundleStore;
  readonly preparedCallContexts: PreparedCallStore;
  readonly chains: ReadonlyMap<number, Readonly<OaathChainCapability>>;
  readonly ownerKey: Readonly<KeyProfile>;
  readonly sessionKey: Readonly<KeyProfile>;
  readonly invalidation: Readonly<OaathCapabilityInvalidationCapability>;
  readonly ownerRevocations: Readonly<OaathOwnerRevocationCapability> | null;
  readonly now: () => number;
}

const GAS_KEYS: readonly string[] = Object.freeze([
  "callGasLimit",
  "verificationGasLimit",
  "preVerificationGas",
  "maxFeePerGas",
  "maxPriorityFeePerGas",
]);

const CHAIN_KEYS: readonly string[] = Object.freeze([
  "chainId",
  "reads",
  "observation",
  "bundler",
  "submission",
  "quote",
  "usage",
  "feePayer",
  "paymasterService",
  "staticPaymasterConfigurationHash",
]);

function unsupported(source: string): never {
  return clientFail("oaath_client_capability_unsupported", "capability is unavailable", source);
}

function requireKernelCapability(chainId: number, capability: KernelCapability): void {
  let fact: ReturnType<typeof diagnoseKernelCapability>;
  try {
    fact = diagnoseKernelCapability({ chainId, capability });
  } catch (error) {
    mapClientFailure(error, "Kernel capability could not be diagnosed");
  }
  if (fact.status !== "available") unsupported(`${capability}:${fact.reason}`);
}

/**
 * Captures a capability object whose required members must all be functions.
 * Narrowing follows the check, and the object itself is handed on unchanged so
 * its own owner (`createKernelRuntime`, `createOperationObserver`,
 * `probeBundlerCapability`) captures it again at its boundary.
 */
function capabilityObject<Capability>(
  value: unknown,
  keys: readonly string[],
  label: string,
  context: CaptureContext,
): Capability {
  const record = exactClientRecord(value, keys, label, context, "oaath_client_capability_invalid");
  for (const key of keys) clientCapability(record[key], `${label} ${key}`);
  return value as Capability;
}

/** Captures one chain capability set exactly; sub-capabilities keep their owners. */
export function captureChainCapability(value: unknown): Readonly<OaathChainCapability> {
  const context: CaptureContext = new WeakSet();
  const captured = captureRecord(value, "OAAth chain capability", context, (message) =>
    clientFail("oaath_client_capability_invalid", message),
  );
  const record = exactCapturedRecord(
    captured,
    [...CHAIN_KEYS, ...(Object.hasOwn(captured, "gas") ? ["gas"] : [])],
    "OAAth chain capability",
    (message) => clientFail("oaath_client_capability_invalid", message),
  );
  const chainId = record.chainId;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
    return clientFail("oaath_client_capability_invalid", "chain capability chainId is invalid");
  }
  let gas: Readonly<KernelGasPolicy>;
  try {
    gas = captureKernelGasPolicy(chainId, record.gas);
  } catch (error) {
    return mapClientFailure(error, "chain gas policy is invalid");
  }
  let paymasterService: Readonly<OaathRegisteredPaymasterService> | null = null;
  if (record.paymasterService !== null) {
    const service = exactClientRecord(
      record.paymasterService,
      ["url", "request", "estimate"],
      "registered paymaster service",
      context,
      "oaath_client_capability_invalid",
    );
    let url: string;
    try {
      url = parseIssuerIdentity({ version: OAATH_ISSUER_VERSION, url: service.url }).url;
    } catch {
      return clientFail(
        "oaath_client_capability_invalid",
        "registered paymaster service URL is invalid",
      );
    }
    paymasterService = Object.freeze({
      url,
      request: clientCapability<Erc7677RegisteredPaymasterService["request"]>(
        service.request,
        "registered paymaster request",
      ),
      estimate: clientCapability<Erc7677GasEstimator["estimate"]>(
        service.estimate,
        "registered paymaster estimate",
      ),
    });
  }
  const staticPaymasterConfigurationHash = record.staticPaymasterConfigurationHash;
  if (
    staticPaymasterConfigurationHash !== null &&
    (typeof staticPaymasterConfigurationHash !== "string" ||
      !USER_OPERATION_HASH.test(staticPaymasterConfigurationHash))
  ) {
    return clientFail(
      "oaath_client_capability_invalid",
      "static paymaster configuration commitment is invalid",
    );
  }
  return Object.freeze({
    chainId,
    gas,
    reads: capabilityObject<OaathChainCapability["reads"]>(
      record.reads,
      ["read"],
      "chain reads",
      context,
    ),
    observation: capabilityObject<OperationObserverCapabilities>(
      record.observation,
      ["read", "close"],
      "chain observation",
      context,
    ),
    bundler: capabilityObject<OaathBundlerProbeCapability>(
      record.bundler,
      ["probe"],
      "chain bundler",
      context,
    ),
    submission: capabilityObject<OaathSubmissionCapability>(
      record.submission,
      ["open"],
      "chain submission",
      context,
    ),
    quote: clientCapability<OaathChainCapability["quote"]>(record.quote, "chain quote"),
    usage:
      record.usage === null
        ? null
        : clientCapability<NonNullable<OaathChainCapability["usage"]>>(record.usage, "chain usage"),
    // routing owns the exact fee-payer rules.
    feePayer: feePayerDescriptor(record.feePayer, context, (message) =>
      clientFail("oaath_client_capability_invalid", message),
    ),
    paymasterService,
    staticPaymasterConfigurationHash: staticPaymasterConfigurationHash as `0x${string}` | null,
  });
}

export function captureCalls(
  value: unknown,
  context: CaptureContext,
): readonly Readonly<KernelV4Call>[] {
  const entries = captureDenseArray(value, "calls", context, (message) =>
    clientFail("oaath_client_input_invalid", message),
  );
  if (entries.length < 1 || entries.length > MAX_CALLS) {
    return clientFail("oaath_client_input_invalid", "calls must hold 1 to 64 entries");
  }
  return Object.freeze(
    entries.map((entry, index) => {
      const record = exactClientRecord(
        entry,
        ["target", "value", "data"],
        `call ${index}`,
        context,
      );
      if (
        typeof record.target !== "string" ||
        typeof record.value !== "string" ||
        typeof record.data !== "string"
      ) {
        return clientFail("oaath_client_input_invalid", `call ${index} fields are invalid`);
      }
      // kernel-v4 owns the exact address, value, and calldata rules.
      return Object.freeze({
        target: record.target as `0x${string}`,
        value: record.value,
        data: record.data as `0x${string}`,
      });
    }),
  );
}

function captureProviderRecoveryInput(value: unknown): Readonly<OperationIdentity> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["identity"],
    "provider operation recovery",
    context,
    "oaath_client_capability_invalid",
  );
  let identity: Readonly<OperationIdentity>;
  try {
    identity = parseOperationIdentity(record.identity);
  } catch {
    return clientFail(
      "oaath_client_capability_invalid",
      "provider operation recovery identity is invalid",
    );
  }
  if (identity.kind !== "execution" || identity.requestHash === null) {
    return clientFail(
      "oaath_client_capability_invalid",
      "provider operation recovery must name a provider execution",
    );
  }
  return identity;
}

function captureProviderPublication(value: unknown): Readonly<OaathProviderOperationPublication> {
  const record = exactClientRecord(
    value,
    ["reserve", "confirm", "abandon"],
    "provider operation publication",
    new WeakSet(),
    "oaath_client_capability_invalid",
  );
  return Object.freeze({
    reserve: clientCapability<OaathProviderOperationPublication["reserve"]>(
      record.reserve,
      "provider operation reservation",
    ),
    confirm: clientCapability<OaathProviderOperationPublication["confirm"]>(
      record.confirm,
      "provider operation confirmation",
    ),
    abandon: clientCapability<OaathProviderOperationPublication["abandon"]>(
      record.abandon,
      "provider operation abandonment",
    ),
  });
}

function captureProviderValidityAdmissionInput(value: unknown): Readonly<{
  chain: number;
  range: Readonly<KernelV4ValidityTimeRange>;
}> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["chain", "range"],
    "provider validity admission",
    context,
    "oaath_client_capability_invalid",
  );
  if (typeof record.chain !== "number" || !Number.isSafeInteger(record.chain) || record.chain < 1) {
    return clientFail(
      "oaath_client_capability_invalid",
      "provider validity admission chain is invalid",
    );
  }
  const range = exactClientRecord(
    record.range,
    ["validAfter", "validUntil"],
    "provider validity range",
    context,
    "oaath_client_capability_invalid",
  );
  if (
    typeof range.validAfter !== "string" ||
    !DECIMAL_UINT48.test(range.validAfter) ||
    typeof range.validUntil !== "string" ||
    !DECIMAL_UINT48.test(range.validUntil)
  ) {
    return clientFail(
      "oaath_client_capability_invalid",
      "provider validity range endpoints are invalid",
    );
  }
  const validAfter = BigInt(range.validAfter);
  const validUntil = BigInt(range.validUntil);
  if (
    validAfter > MAX_UINT48 ||
    validUntil > MAX_UINT48 ||
    validUntil === 0n ||
    validAfter >= validUntil
  ) {
    return clientFail("oaath_client_capability_invalid", "provider validity range is invalid");
  }
  return Object.freeze({
    chain: record.chain,
    range: Object.freeze({
      validAfter: validAfter.toString(10),
      validUntil: validUntil.toString(10),
    }),
  });
}

function coverageToRouting(result: GrantPolicyCoverageResult): OaathSessionCoverage {
  if (result.status === "covered") return "covered";
  return result.status === "denied" ? "uncovered" : "unreadable";
}

export function quoteFields(value: unknown): Readonly<{
  nonceKey: string;
  sequence: string;
  gas: Readonly<KernelV4UserOperationGas>;
}> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["nonceKey", "sequence", "gas"],
    "operation quote",
    context,
    "oaath_client_capability_invalid",
  );
  if (typeof record.nonceKey !== "string" || typeof record.sequence !== "string") {
    return clientFail("oaath_client_capability_invalid", "operation quote nonce is invalid");
  }
  const gas = exactClientRecord(
    record.gas,
    GAS_KEYS,
    "operation quote gas",
    context,
    "oaath_client_capability_invalid",
  );
  const fields: Record<string, string> = {};
  for (const key of GAS_KEYS) {
    const field = gas[key];
    if (typeof field !== "string") {
      return clientFail("oaath_client_capability_invalid", "operation quote gas is invalid");
    }
    fields[key] = field;
  }
  // prepareKernelV4UserOperation owns the exact numeric bounds of every field.
  return Object.freeze({
    nonceKey: record.nonceKey,
    sequence: record.sequence,
    gas: Object.freeze({
      callGasLimit: fields.callGasLimit ?? "",
      verificationGasLimit: fields.verificationGasLimit ?? "",
      preVerificationGas: fields.preVerificationGas ?? "",
      maxFeePerGas: fields.maxFeePerGas ?? "",
      maxPriorityFeePerGas: fields.maxPriorityFeePerGas ?? "",
    }),
  });
}

export function captureSubmissionSession(value: unknown): Readonly<OperationSubmissionSession> {
  const context: CaptureContext = new WeakSet();
  const record = exactClientRecord(
    value,
    ["send", "close"],
    "submission session",
    context,
    "oaath_client_capability_invalid",
  );
  return Object.freeze({
    submit: clientCapability<() => Promise<unknown>>(record.send, "submission session send"),
    close: clientCapability<() => Promise<void>>(record.close, "submission session close"),
  });
}

export function createGrantHandle(
  input: Readonly<CreateGrantHandleInput>,
): Readonly<OaathGrantHandle> {
  interface ValidityAdmissionEvidence {
    readonly chainId: number;
    readonly range: Readonly<KernelV4ValidityTimeRange>;
    readonly runtime: Readonly<GrantKernelRuntime>;
    readonly descriptor: Readonly<GrantKernelAccount>;
  }

  interface ExecutionRouteAdmissionEvidence {
    readonly chainId: number;
    readonly bundler: OaathBundlerCapability;
  }

  let record = input.record;
  let closed = false;
  let closeRequested = false;
  let closing: Promise<void> | null = null;
  let revocationRequested = false;
  let revoking: Promise<void> | null = null;
  let activeExecutions = 0;
  let activeActivities = 0;
  const executionWaiters = new Set<() => void>();
  const activityWaiters = new Set<() => void>();
  const observers = new Map<number, OperationObserver>();
  const handles = new Set<Readonly<OaathOperationHandle>>();
  const validatedPreparedCalls = new WeakMap<
    object,
    Readonly<{
      shape: Readonly<ExecutionShape>;
      plan: Readonly<OaathExternalPreparedCallPlan>;
      signature: `0x${string}`;
    }>
  >();
  const validityAdmissions = new WeakMap<object, Readonly<ValidityAdmissionEvidence>>();
  const executionRouteAdmissions = new WeakMap<object, Readonly<ExecutionRouteAdmissionEvidence>>();
  const unsupportedValidityAdmission = Object.freeze({ status: "unsupported" as const });
  const supportedValidityTimeRange = Object.freeze({ status: "supported" as const });
  const unsupportedValidityTimeRange = Object.freeze({ status: "unsupported" as const });

  function assertOpen(): void {
    if (closed || closeRequested) clientFail("oaath_client_closed", "Grant handle is closed");
  }

  function releaseExecution(): void {
    activeExecutions -= 1;
    if (activeExecutions !== 0) return;
    for (const resolve of executionWaiters) resolve();
    executionWaiters.clear();
  }

  function waitForExecutions(): Promise<void> {
    if (activeExecutions === 0) return Promise.resolve();
    return new Promise((resolve) => executionWaiters.add(resolve));
  }

  async function withExecution<Result>(action: () => Promise<Result>): Promise<Result> {
    assertOpen();
    if (revocationRequested) {
      return clientFail(
        "oaath_client_grant_inactive",
        "Grant revocation has started",
        "grant_revocation_requested",
      );
    }
    activeExecutions += 1;
    try {
      return await action();
    } finally {
      releaseExecution();
    }
  }

  function releaseActivity(): void {
    activeActivities -= 1;
    if (activeActivities !== 0) return;
    for (const resolve of activityWaiters) resolve();
    activityWaiters.clear();
  }

  function waitForActivities(): Promise<void> {
    if (activeActivities === 0) return Promise.resolve();
    return new Promise((resolve) => activityWaiters.add(resolve));
  }

  async function withActivity<Result>(action: () => Promise<Result>): Promise<Result> {
    assertOpen();
    activeActivities += 1;
    try {
      return await action();
    } finally {
      releaseActivity();
    }
  }

  function requireExecutionPublication(): void {
    if (closeRequested) clientFail("oaath_client_closed", "Grant handle is closing");
    if (revocationRequested) {
      clientFail(
        "oaath_client_grant_inactive",
        "Grant revocation started before operation publication",
        "grant_revocation_requested",
      );
    }
  }

  function chainCapability(chainId: number): Readonly<OaathChainCapability> {
    const chain = input.chains.get(chainId);
    if (!chain) unsupported("chain_not_configured");
    return chain;
  }

  function classifiedBundler(
    chainId: number,
    chain: Readonly<OaathChainCapability>,
    entryPoint: `0x${string}`,
  ): Promise<OaathBundlerCapability> {
    return probeBundlerCapability({
      capability: chain.bundler,
      request: { chainId, entryPoint },
      timeoutMs: SUBMISSION_TIMEOUT_MS,
    }).catch((error: unknown) => mapClientFailure(error, "bundler probe failed"));
  }

  async function refresh(): Promise<GrantStoreRecord> {
    let current: GrantStoreRecord | undefined;
    try {
      current = await input.grants.get(record.value.identity.grantId);
    } catch (error) {
      return mapClientFailure(error, "Grant record could not be read");
    }
    if (!current) {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant record disappeared",
        "grant_record_absent",
      );
    }
    record = current;
    return current;
  }

  async function commit(
    previous: Readonly<GrantStoreRecord>,
    next: Grant,
  ): Promise<GrantStoreRecord> {
    try {
      const committed = await input.grants.compareAndSwap({
        grantId: previous.value.identity.grantId,
        expectedStoreRevision: previous.storeRevision,
        next,
      });
      if (committed.status === "conflict") {
        if (committed.current !== undefined) record = committed.current;
        return clientFail(
          "oaath_client_state_conflict",
          "another writer advanced the Grant",
          "grant_store_conflict",
        );
      }
      record = committed.record;
      return committed.record;
    } catch (error) {
      return mapClientFailure(error, "Grant transition could not be committed");
    }
  }

  function transition(grant: Grant, change: GrantTransition): Grant {
    try {
      return advanceGrant(grant, change);
    } catch (error) {
      return mapClientFailure(error, "Grant transition is not allowed");
    }
  }

  async function requireActive(): Promise<GrantStoreRecord> {
    const current = await refresh();
    const grant = current.value;
    if (grant.state !== "active") {
      clientFail("oaath_client_grant_inactive", "the Grant is not active", `grant_${grant.state}`);
    }
    if (input.now() >= grant.expiresAt) {
      clientFail("oaath_client_grant_inactive", "the Grant is expired", "grant_expired");
    }
    return current;
  }

  function ownerRuntime(chainId: number): Readonly<GrantKernelRuntime> {
    const chain = chainCapability(chainId);
    try {
      return createGrantKernelRuntime({
        account: input.binding.account,
        ownerKey: input.ownerKey,
        chainId,
        operator: ownerOperator({ key: input.ownerKey }),
        reads: chain.reads,
        ...(chain.gas === undefined ? {} : { gas: chain.gas }),
      });
    } catch (error) {
      return mapClientFailure(error, "owner runtime could not be composed");
    }
  }

  function sessionRuntime(chainId: number): Readonly<GrantKernelRuntime> {
    const chain = chainCapability(chainId);
    try {
      return createGrantKernelRuntime({
        account: input.binding.account,
        ownerKey: input.ownerKey,
        chainId,
        // The session composition point is opaque here: this handle supplies the
        // key and the policy profiles derived from the approved Grant scope, and
        // never reaches into how the authority is installed.
        operator: sessionOperator({
          key: input.sessionKey,
          policies: deriveSessionPolicyProfiles(input.approvedPolicy),
        }),
        reads: chain.reads,
        ...(chain.gas === undefined ? {} : { gas: chain.gas }),
      });
    } catch (error) {
      return mapClientFailure(error, "session runtime could not be composed");
    }
  }

  /**
   * Account identity comes from the approved versioned profile and owner:
   * v4 binds initial packages; v3.3 proves the existing address and current owner.
   *
   * The descriptor is bound per send and never cached. A descriptor freezes the
   * account state observed at bind time, so reusing one after the account's first
   * operation deployed it would carry stale factory evidence.
   */
  async function accountDescriptor(
    chainId: number,
    bindingRuntime?: Readonly<GrantKernelRuntime>,
  ): Promise<Readonly<GrantKernelAccount>> {
    const runtime = bindingRuntime ?? ownerRuntime(chainId);
    try {
      return await runtime.bindAccount();
    } catch (error) {
      return mapClientFailure(error, "Kernel account could not be bound");
    }
  }

  function observer(chainId: number): OperationObserver {
    const cached = observers.get(chainId);
    if (cached) return cached;
    try {
      const created = createOperationObserver(chainCapability(chainId).observation);
      observers.set(chainId, created);
      return created;
    } catch (error) {
      return mapClientFailure(error, "operation observer could not be composed");
    }
  }

  function operationStore(): OperationStore {
    return new OperationStore({
      get: (key: Readonly<OperationStoreKey>) => input.operations.get(key),
      getArchived: (value: Parameters<OperationStoreAdapter["getArchived"]>[0]) =>
        input.operations.getArchived(value),
      compareAndSwap: (value: Parameters<OperationStoreAdapter["compareAndSwap"]>[0]) =>
        input.operations.compareAndSwap(value),
      close: async () => undefined,
    } satisfies OperationStoreAdapter);
  }

  async function sessionCoverage(
    grant: Grant,
    chainId: number,
    calls: readonly Readonly<KernelV4Call>[],
    identity: Readonly<{ account: `0x${string}`; permissionId: `0x${string}` }>,
  ): Promise<OaathSessionCoverage> {
    const chain = chainCapability(chainId);
    let usage: unknown = null;
    if (chain.usage) {
      try {
        usage = await chain.usage(
          Object.freeze({
            grantId: grant.identity.grantId,
            chainId,
            ...identity,
            maximumOperations: input.approvedPolicy.perChainOperationLimit.toString(10),
          }),
        );
      } catch {
        // An unavailable usage read is inconclusive, never "unused".
        return "unreadable";
      }
    }
    try {
      return coverageToRouting(
        evaluateGrantPolicyCoverage({
          policy: input.approvedPolicy,
          grantId: grant.identity.grantId,
          chainId,
          evaluatedAt: input.now(),
          calls: calls.map((call) =>
            Object.freeze({ target: call.target, data: call.data, value: call.value }),
          ),
          usage: usage === undefined ? null : usage,
        }),
      );
    } catch {
      // Hostile usage evidence or a call the policy vocabulary cannot express is
      // inconclusive, so the decision table requires owner authority. The send
      // itself still fails closed later if the call is malformed.
      return "unreadable";
    }
  }

  interface ExecutionShape {
    readonly chainId: number;
    readonly chain: Readonly<OaathChainCapability>;
    readonly runtime: Readonly<GrantKernelRuntime>;
    readonly descriptor: Readonly<GrantKernelAccount>;
    readonly calls: readonly Readonly<KernelV4Call>[];
    readonly mode: "standard" | "enable-replayable";
    readonly materializer: GrantKernelExecution | null;
    readonly decision: Readonly<OaathExecutionDecision>;
    readonly binding: Readonly<{
      chainId: number;
      account: `0x${string}`;
      permissionId: `0x${string}`;
    }>;
    readonly grantId: string;
    readonly grantExpiresAt: number;
    readonly validityTimeRange?: Readonly<KernelV4ValidityTimeRange>;
  }

  /** Shared pre-effect checks for public review and operation execution. */
  async function resolveExecutionRead(
    chainId: number,
    calls: readonly Readonly<KernelV4Call>[],
    validityAdmission: Readonly<ValidityAdmissionEvidence> | null = null,
    executionRouteAdmission: Readonly<ExecutionRouteAdmissionEvidence> | null = null,
  ) {
    const grantSnapshot = await requireActive();
    const grant = grantSnapshot.value;
    const chain = chainCapability(chainId);
    requireKernelCapability(chainId, kernelKeyCapability("owner", input.ownerKey.kind));
    requireKernelCapability(chainId, kernelKeyCapability("session", input.sessionKey.kind));
    requireKernelCapability(chainId, "hook_call");
    const runtime = validityAdmission?.runtime ?? sessionRuntime(chainId);
    const descriptor = validityAdmission?.descriptor ?? (await accountDescriptor(chainId, runtime));
    if (runtime.validation.kind !== "permission") {
      return unsupported("session_validation_not_permission");
    }
    const coverage = await sessionCoverage(grant, chainId, calls, {
      account: descriptor.account,
      permissionId: runtime.validation.permissionId,
    });
    if (coverage !== "covered") {
      return clientFail(
        "oaath_client_scope_denied",
        coverage === "uncovered"
          ? "the calls are outside the approved Grant scope"
          : "Grant scope coverage could not be conclusively evaluated",
        coverage === "uncovered" ? "session_calls_uncovered" : "session_coverage_unreadable",
      );
    }
    const bundler =
      executionRouteAdmission?.bundler ??
      (await classifiedBundler(chainId, chain, runtime.deployment.entryPoint.address));
    const decision = decideExecution({
      operationKind: "execution",
      sessionCoverage: coverage,
      bundler,
      feePayer: chain.feePayer,
    });
    if (decision.route === "none") {
      return clientFail(
        "oaath_client_route_unavailable",
        "no safe submission route is available",
        decision.reasons.join(","),
      );
    }
    return Object.freeze({ grantSnapshot, chain, runtime, descriptor, decision });
  }

  async function resolveExecutionShape(
    chainId: number,
    calls: readonly Readonly<KernelV4Call>[],
    validityAdmission: Readonly<ValidityAdmissionEvidence> | null = null,
    executionRouteAdmission: Readonly<ExecutionRouteAdmissionEvidence> | null = null,
  ): Promise<Readonly<ExecutionShape>> {
    const { grantSnapshot, chain, runtime, descriptor, decision } = await resolveExecutionRead(
      chainId,
      calls,
      validityAdmission,
      executionRouteAdmission,
    );
    requireExecutionPublication();
    let publicationSnapshot = await requireActive();
    requireExecutionPublication();
    if (publicationSnapshot.storeRevision !== grantSnapshot.storeRevision) {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant advanced before operation publication",
        "grant_store_conflict",
      );
    }
    let publicationGrant = publicationSnapshot.value;
    if (runtime.validation.kind !== "permission") {
      return unsupported("session_validation_not_permission");
    }
    const binding = Object.freeze({
      chainId,
      account: descriptor.account,
      permissionId: runtime.validation.permissionId,
    });
    let materialization = publicationGrant.materializations.find(
      (entry) => entry.chainId === chainId && entry.state !== "unsupported",
    );
    if (materialization?.state === "installing") {
      publicationSnapshot = await reconcileInstallingMaterialization(
        publicationSnapshot,
        binding,
        materialization.operationId,
      );
      publicationGrant = publicationSnapshot.value;
      materialization = publicationGrant.materializations.find(
        (entry) => entry.chainId === chainId && entry.state !== "unsupported",
      );
    }
    let mode: "standard" | "enable-replayable" = "standard";
    let latest = publicationSnapshot;
    if (materialization === undefined || materialization.state === "unmaterialized") {
      if (input.installApproval === null) {
        return unsupported("grant_capability_unavailable");
      }
      mode = "enable-replayable";
      if (materialization === undefined) {
        latest = await commit(
          latest,
          transition(latest.value, {
            type: "record_unmaterialized",
            identity: latest.value.identity,
            binding,
            recordedAt: input.now(),
          }),
        );
        publicationGrant = latest.value;
      }
    } else if (materialization.state === "installing") {
      if (input.installApproval === null) {
        return unsupported("grant_capability_unavailable");
      }
      mode = "enable-replayable";
    } else if (materialization.state !== "installed") {
      return unsupported(`grant_materialization_${materialization.state}`);
    }

    return Object.freeze({
      chainId,
      chain,
      runtime,
      descriptor,
      calls,
      mode,
      materializer:
        mode === "enable-replayable" ? permissionMaterializer(runtime, descriptor.account) : null,
      decision,
      binding,
      grantId: publicationGrant.identity.grantId,
      grantExpiresAt: publicationGrant.expiresAt,
      ...(validityAdmission === null ? {} : { validityTimeRange: validityAdmission.range }),
    });
  }

  function permissionMaterializer(
    runtime: Readonly<GrantKernelRuntime>,
    account: `0x${string}`,
  ): GrantKernelExecution {
    const approval = input.installApproval;
    if (approval === null) return unsupported("grant_capability_unavailable");
    try {
      return runtime.bindApproval(approval, account);
    } catch (error) {
      return mapClientFailure(error, "the install approval does not bind this permission runtime");
    }
  }

  type PreparedCallPaymasterSource =
    | Readonly<{
        kind: "resolve-erc7677";
        sponsorship: Readonly<OaathKernelSponsorshipCapability>;
        resultCapabilities: () => Readonly<OaathWalletCallResultCapabilities> | null;
      }>
    | Readonly<{ kind: "retained"; paymaster: Readonly<PreparedPaymaster> }>
    | null;

  /** The runtime owns every simulated byte, including enable and validity envelopes. */
  function quoteRequest(
    spec: Readonly<{
      chainId: number;
      kind: OperationKind;
      signer: OaathExecutionSigner;
      grantId: string;
      runtime: Readonly<GrantKernelRuntime>;
      materializer: GrantKernelExecution | null;
      descriptor: Readonly<GrantKernelAccount>;
      mode: "standard" | "enable-replayable";
      calls: readonly Readonly<KernelV4Call>[];
      validityTimeRange?: Readonly<KernelV4ValidityTimeRange>;
    }>,
    paymaster: Readonly<PreparedPaymaster> | null,
    purpose: OaathQuoteRequest["purpose"],
    retainedGas?: Readonly<KernelV4UserOperationGas>,
  ): Readonly<OaathQuoteRequest> {
    const execution = spec.materializer ?? spec.runtime;
    const prepared = execution.prepareOperation({
      kind: spec.kind,
      grantId: spec.grantId,
      account: spec.descriptor,
      nonceKey: "0",
      sequence: "0",
      calls: [...spec.calls],
      gas: retainedGas ?? {
        callGasLimit: "0",
        verificationGasLimit: "0",
        preVerificationGas: "0",
        maxFeePerGas: "0",
        maxPriorityFeePerGas: "0",
      },
      paymaster,
      ...(spec.validityTimeRange === undefined
        ? {}
        : { validityTimeRange: spec.validityTimeRange }),
    });
    return Object.freeze({
      purpose,
      chainId: spec.chainId,
      kind: spec.kind,
      signer: spec.signer,
      account: spec.descriptor.account,
      mode: spec.mode,
      validation: spec.runtime.validation,
      calls: spec.calls,
      paymaster,
      simulation: Object.freeze({ prepared, signature: execution.dummySignature }),
    });
  }

  async function prepareExecutionShape(
    shape: Readonly<ExecutionShape>,
    options: Readonly<{
      gas?: Readonly<KernelV4UserOperationGas>;
      paymaster?: PreparedCallPaymasterSource;
    }> = {},
  ): Promise<
    Readonly<{
      prepared: Readonly<PreparedUserOperation>;
      quote: Readonly<{ nonceKey: string; sequence: string }>;
      resultCapabilities: Readonly<OaathWalletCallResultCapabilities> | null;
    }>
  > {
    const paymaster = options.paymaster?.kind === "retained" ? options.paymaster.paymaster : null;
    const quote = quoteFields(
      await shape.chain.quote(
        quoteRequest(
          { ...shape, kind: "execution", signer: "session" },
          paymaster,
          options.gas !== undefined
            ? "revalidate"
            : options.paymaster?.kind === "resolve-erc7677"
              ? "sponsorship"
              : "estimate",
          options.gas,
        ),
      ),
    );
    const fields = {
      grantId: shape.grantId,
      account: shape.descriptor,
      nonceKey: quote.nonceKey,
      sequence: quote.sequence,
      calls: [...shape.calls],
      gas: options.gas ?? quote.gas,
      paymaster,
      ...(shape.validityTimeRange === undefined
        ? {}
        : { validityTimeRange: shape.validityTimeRange }),
    };
    const execution = shape.materializer ?? shape.runtime;
    const operation: GrantKernelPrepareInput = { kind: "execution", ...fields };
    let resultCapabilities: Readonly<OaathWalletCallResultCapabilities> | null = null;
    const prepared =
      options.paymaster?.kind === "resolve-erc7677"
        ? await prepareSponsoredKernelOperation({
            runtime: execution,
            operation,
            simulationSignature: execution.dummySignature,
            sponsorship: options.paymaster.sponsorship,
          })
        : execution.prepareOperation(operation);
    if (options.paymaster?.kind === "resolve-erc7677") {
      resultCapabilities = options.paymaster.resultCapabilities();
    }
    return Object.freeze({
      prepared,
      quote: Object.freeze({ nonceKey: quote.nonceKey, sequence: quote.sequence }),
      resultCapabilities,
    });
  }

  async function finalExternalSignature(
    shape: Readonly<ExecutionShape>,
    prepared: Readonly<PreparedUserOperation>,
    signature: `0x${string}`,
  ): Promise<`0x${string}`> {
    try {
      return await (shape.materializer ?? shape.runtime).encodeVerifiedSignature(
        prepared,
        signature,
      );
    } catch (error) {
      return mapClientFailure(error, "prepared-call signature could not be verified");
    }
  }

  function runner(spec: {
    readonly connectedFeePayer?: Readonly<ConnectedEoa> | null;
    readonly chainId: number;
    readonly kind: OperationKind;
    readonly runtime: Readonly<GrantKernelRuntime>;
    readonly descriptor: Readonly<GrantKernelAccount>;
    readonly calls: readonly Readonly<KernelV4Call>[];
    /** The proven authority; a denied decision never reaches a runner. */
    readonly signer: OaathExecutionSigner;
    /**
     * `enable-replayable` spends the owner's install approval on this chain:
     * the prepared operation installs the permission and executes together,
     * and its signature is Kernel's enable envelope rather than a plain
     * session signature.
     */
    readonly mode: "standard" | "enable-replayable";
    readonly materializer: GrantKernelExecution | null;
    readonly decision: Readonly<OaathExecutionDecision>;
    readonly terminalBehavior: "replace" | "reuse_same_kind";
    readonly grantId: string;
    readonly requestHash: `0x${string}` | null;
    readonly validityTimeRange?: Readonly<KernelV4ValidityTimeRange>;
    readonly publication?: Readonly<OaathProviderOperationPublication>;
    readonly authorizeOperation?: (operation: OaathProviderOperationPointer) => Promise<void>;
    readonly abandonOperation?: (operation: OaathProviderOperationPointer) => Promise<void>;
    readonly prepared?: Readonly<PreparedUserOperation>;
    /** Display-only facts retained with an already prepared operation. */
    readonly preparedResultCapabilities?: Readonly<OaathWalletCallResultCapabilities> | null;
    /** Already locally verified and fully wrapped; retained in memory only. */
    readonly externalSignature?: `0x${string}`;
    /** Present only while one final sponsored identity is being prepared. */
    readonly sponsorship?: Readonly<OaathKernelSponsorshipCapability>;
    /** Display-only result facts available after that sponsorship completed. */
    readonly sponsorshipResultCapabilities?: () => Readonly<OaathWalletCallResultCapabilities> | null;
    /** Present only for one authenticated ERC-7902 static configuration. */
    readonly staticPaymaster?: Readonly<PreparedPaymaster>;
  }): ReturnType<typeof createOperationRunner> {
    const chain = chainCapability(spec.chainId);
    const execution = spec.materializer ?? spec.runtime;
    const shared = observer(spec.chainId);
    let reservedOperation: OaathProviderOperationPointer | null = null;
    let resultCapabilities: Readonly<OaathWalletCallResultCapabilities> | null =
      spec.preparedResultCapabilities ?? null;
    let publicationConfirmed = false;
    try {
      return createOperationRunner({
        terminalBehavior: spec.terminalBehavior,
        requestHash: spec.requestHash,
        // A scoped store and facades: the realm owns the adapter, the observer,
        // and the caller's transports, so closing one runner never disables
        // another that still has work.
        store: operationStore(),
        observer: {
          observeOperation: (value: unknown) => shared.observeOperation(value),
          close: async () => undefined,
        },
        preparation: {
          prepare: async () => {
            if (spec.prepared !== undefined) return spec.prepared;
            const quote = quoteFields(
              await chain.quote(
                quoteRequest(
                  spec,
                  spec.staticPaymaster ?? null,
                  spec.sponsorship === undefined ? "estimate" : "sponsorship",
                ),
              ),
            );
            const fields = {
              grantId: spec.grantId,
              account: spec.descriptor,
              nonceKey: quote.nonceKey,
              sequence: quote.sequence,
              calls: [...spec.calls],
              gas: quote.gas,
              paymaster: spec.staticPaymaster ?? null,
              ...(spec.validityTimeRange === undefined
                ? {}
                : { validityTimeRange: spec.validityTimeRange }),
            };
            const operation: GrantKernelPrepareInput = { kind: spec.kind, ...fields };
            if (spec.sponsorship === undefined) {
              return execution.prepareOperation(operation);
            }
            const prepared = await prepareSponsoredKernelOperation({
              runtime: execution,
              operation,
              simulationSignature: execution.dummySignature,
              sponsorship: spec.sponsorship,
            });
            resultCapabilities = spec.sponsorshipResultCapabilities?.() ?? null;
            return prepared;
          },
          reserveOperation: async (prepared: PreparedUserOperation) => {
            if (!spec.publication) return;
            if (reservedOperation !== null) {
              return clientFail(
                "oaath_client_internal",
                "the provider operation reservation was invoked more than once",
              );
            }
            const identity = deriveOperationId(prepared, spec.requestHash);
            const exact: OaathProviderOperationPointer = Object.freeze({ identity });
            await spec.publication.reserve(Object.freeze({ operation: exact, resultCapabilities }));
            reservedOperation = exact;
          },
          releaseOperationReservation: async (prepared: PreparedUserOperation) => {
            if (!spec.publication || reservedOperation === null) return;
            const exact = Object.freeze({
              identity: deriveOperationId(prepared, spec.requestHash),
            });
            if (!sameProviderOperationPointer(reservedOperation, exact)) {
              return clientFail(
                "oaath_client_internal",
                "the provider operation reservation release is inconsistent",
              );
            }
            await spec.publication.abandon(exact);
          },
          authorizeOperation: async (prepared: PreparedUserOperation) => {
            if (!spec.authorizeOperation) return;
            await spec.authorizeOperation(
              Object.freeze({ identity: deriveOperationId(prepared, spec.requestHash) }),
            );
          },
          abandonOperation: async (prepared: PreparedUserOperation) => {
            const exact = Object.freeze({
              identity: deriveOperationId(prepared, spec.requestHash),
            });
            let failure: unknown;
            if (spec.abandonOperation) {
              await spec.abandonOperation(exact).catch((error: unknown) => {
                failure = error;
              });
            }
            if (spec.publication && reservedOperation !== null) {
              if (!sameProviderOperationPointer(reservedOperation, exact)) {
                failure ??= new Error("provider operation abandonment identity mismatch");
              } else {
                await spec.publication.abandon(exact).catch((error: unknown) => {
                  failure ??= error;
                });
              }
            }
            if (failure !== undefined) throw failure;
          },
          confirmOperationPublished: async (prepared: PreparedUserOperation) => {
            if (!spec.publication) return;
            if (
              reservedOperation === null ||
              publicationConfirmed ||
              !sameProviderOperationPointer(reservedOperation, {
                identity: deriveOperationId(prepared, spec.requestHash),
              })
            ) {
              return clientFail(
                "oaath_client_internal",
                "the provider operation publication confirmation is inconsistent",
              );
            }
            await spec.publication.confirm(reservedOperation);
            publicationConfirmed = true;
          },
          close: async () => undefined,
        },
        submission: {
          openSubmission: async (prepared: PreparedUserOperation) => {
            // The authority signs the already-durable snapshot; the route was
            // decided before any signature existed and cannot change it. The
            // enable envelope is minted here, after provider binding and the
            // runner's durable submission-attempt transition, for this exact
            // snapshot and nothing else.
            const signature = spec.externalSignature ?? (await execution.signOperation(prepared));
            const submission = {
              prepared,
              signature,
              route: spec.decision.route,
              feePayer: spec.decision.feePayer,
            };
            return withConnectedEoaFallback(
              captureSubmissionSession(await chain.submission.open(submission)),
              submission,
              spec.connectedFeePayer ?? null,
            );
          },
          close: async () => undefined,
        },
      });
    } catch (error) {
      return mapClientFailure(error, "operation runner could not be composed");
    }
  }

  function observationOnlyRunner(chainId: number): ReturnType<typeof createOperationRunner> {
    const shared = observer(chainId);
    try {
      return createOperationRunner({
        terminalBehavior: "reuse_same_kind",
        requestHash: null,
        store: operationStore(),
        observer: {
          observeOperation: (value: unknown) => shared.observeOperation(value),
          close: async () => undefined,
        },
        preparation: {
          prepare: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot prepare",
            ),
          reserveOperation: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot reserve publication",
            ),
          releaseOperationReservation: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot release publication",
            ),
          authorizeOperation: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot authorize publication",
            ),
          abandonOperation: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot abandon publication",
            ),
          confirmOperationPublished: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot confirm publication",
            ),
          close: async () => undefined,
        },
        submission: {
          openSubmission: async () =>
            clientFail(
              "oaath_client_internal",
              "an observation-only provider runner cannot submit",
            ),
          close: async () => undefined,
        },
      });
    } catch (error) {
      return mapClientFailure(error, "provider observation runner could not be composed");
    }
  }

  async function exactOperation(
    key: Readonly<OperationStoreKey>,
    userOperationHash: `0x${string}`,
  ): Promise<OperationStoreRecord | undefined> {
    const journal = operationStore();
    try {
      return await journal.getExact(key, userOperationHash);
    } catch (error) {
      return mapClientFailure(error, "provider operation history could not be read");
    } finally {
      await journal.close().catch(() => undefined);
    }
  }

  function trackedOperationHandle(
    handleInput: Readonly<Parameters<typeof createOperationHandle>[0]>,
  ): Readonly<OaathOperationHandle> {
    let created: Readonly<OaathOperationHandle>;
    created = createOperationHandle({
      ...handleInput,
      onClosed: () => handles.delete(created),
    });
    handles.add(created);
    return created;
  }

  function observationHandle(
    key: Readonly<OperationStoreKey>,
    record: OperationStoreRecord,
  ): Readonly<OaathOperationHandle> {
    return trackedOperationHandle({
      runner: observationOnlyRunner(key.chainId),
      key,
      kind: "execution",
      timeoutMs: SUBMISSION_TIMEOUT_MS,
      now: input.now,
      initial: Object.freeze({ status: "started" as const, record }),
      observation: chainCapability(key.chainId).observation.read,
      onObserved: (observed: OperationObserveResult) =>
        recordRecoveredMaterialization(record.value.identity.account, observed),
    });
  }

  async function recoverOperationWork(
    value: unknown,
  ): Promise<Readonly<OaathProviderOperationRecovery>> {
    assertOpen();
    const exact = captureProviderRecoveryInput(value);
    if (exact.grantId !== record.value.identity.grantId) {
      return clientFail(
        "oaath_client_state_conflict",
        "provider operation belongs to another Grant",
        "provider_operation_grant_mismatch",
      );
    }
    const key = Object.freeze({
      grantId: exact.grantId,
      chainId: exact.chainId,
      kind: "execution" as const,
    });
    const operationRecord = await exactOperation(key, exact.userOperationHash);
    if (operationRecord === undefined) return Object.freeze({ status: "absent" as const });
    const retained = operationRecord.value.identity;
    if (
      retained.kind !== exact.kind ||
      retained.grantId !== exact.grantId ||
      retained.chainId !== exact.chainId ||
      retained.entryPoint !== exact.entryPoint ||
      retained.account !== exact.account ||
      retained.nonce !== exact.nonce ||
      retained.userOperationHash !== exact.userOperationHash
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "provider operation identity contradicts its durable publication",
        "provider_operation_identity_mismatch",
      );
    }
    if (retained.requestHash !== exact.requestHash) {
      return Object.freeze({ status: "request_conflict" as const });
    }
    if (operationRecord.value.state === "abandoned") {
      await releaseAbandonedMaterialization(exact).catch(() => undefined);
      return Object.freeze({ status: "abandoned" as const });
    }

    if (operationRecord.value.state === "prepared") {
      return Object.freeze({ status: "prepared" as const });
    }

    return Object.freeze({
      status: "observable" as const,
      operation: observationHandle(key, operationRecord),
    });
  }

  async function releaseAbandonedMaterialization(
    exact: Readonly<OperationIdentity>,
  ): Promise<void> {
    const snapshot = await refresh();
    const grant = snapshot.value;
    if (grant.state !== "active" && grant.state !== "revoking") return;
    const current = grant.materializations.find(
      (entry) => entry.chainId === exact.chainId && entry.state !== "unsupported",
    );
    if (
      current?.state !== "installing" ||
      current.account !== exact.account ||
      current.operationId !== exact.userOperationHash
    ) {
      return;
    }
    const abandonedAt = materializationReleaseTime(grant);
    await commit(
      snapshot,
      transition(grant, {
        type: "abandon_materialization",
        identity: grant.identity,
        binding: {
          chainId: current.chainId,
          account: current.account,
          permissionId: current.permissionId,
        },
        operationId: exact.userOperationHash,
        abandonedAt,
      }),
    );
  }

  async function abandonPreparedOperationWork(
    value: unknown,
  ): Promise<Readonly<OaathProviderOperationRecovery>> {
    const exact = captureProviderRecoveryInput(value);
    const current = await recoverOperationWork(Object.freeze({ identity: exact }));
    if (current.status !== "prepared") return current;
    const abandoning = observationOnlyRunner(exact.chainId);
    try {
      await abandoning.abandonPreparedOperation({
        kind: "execution",
        key: {
          grantId: exact.grantId,
          chainId: exact.chainId,
          kind: "execution",
        },
        expectedUserOperationHash: exact.userOperationHash,
        abandonedAt: input.now(),
      });
    } catch {
      // The exact reread below decides whether submission won the CAS.
    } finally {
      await abandoning.close().catch(() => undefined);
    }
    return recoverOperationWork(Object.freeze({ identity: exact }));
  }

  async function runOnce(
    created: ReturnType<typeof createOperationRunner>,
    kind: OperationKind,
    key: Readonly<OperationStoreKey>,
  ): Promise<OperationRunResult> {
    const at = input.now();
    try {
      return await created.runOperation({
        kind,
        key,
        preparedAt: at,
        attemptedAt: at,
        submittedAt: at,
        observedAt: at,
        timeoutMs: SUBMISSION_TIMEOUT_MS,
      });
    } catch (error) {
      return mapClientFailure(error, "operation run failed");
    }
  }

  async function startOnce(
    created: ReturnType<typeof createOperationRunner>,
    kind: OperationKind,
    key: Readonly<OperationStoreKey>,
  ): Promise<OperationStartResult> {
    const at = input.now();
    try {
      return await created.startOperation({
        kind,
        key,
        preparedAt: at,
        attemptedAt: at,
        submittedAt: at,
        observedAt: at,
        timeoutMs: SUBMISSION_TIMEOUT_MS,
      });
    } catch (error) {
      return mapClientFailure(error, "operation start failed");
    }
  }

  async function resumePreparedOnce(
    created: ReturnType<typeof createOperationRunner>,
    key: Readonly<OperationStoreKey>,
    expectedUserOperationHash: `0x${string}`,
  ): Promise<OperationStartResult> {
    const at = input.now();
    try {
      return await created.resumePreparedOperation({
        kind: "execution",
        key,
        preparedAt: at,
        attemptedAt: at,
        submittedAt: at,
        observedAt: at,
        timeoutMs: SUBMISSION_TIMEOUT_MS,
        expectedUserOperationHash,
      });
    } catch (error) {
      return mapClientFailure(error, "prepared operation resume failed");
    }
  }

  async function recordFinalizedMaterialization(
    binding: Readonly<{
      chainId: number;
      account: `0x${string}`;
      permissionId: `0x${string}`;
    }>,
    result: OperationRunResult | OperationStartResult,
  ): Promise<void> {
    if (result.status !== "observed") return;
    const value = result.record.value;
    if (value.state !== "finalized") return;
    if (value.identity.chainId !== binding.chainId || value.identity.account !== binding.account) {
      return clientFail(
        "oaath_client_state_conflict",
        "finalized installation operation does not match its Grant binding",
        "grant_materialization_operation_mismatch",
      );
    }

    const snapshot = await refresh();
    const grant = snapshot.value;
    const current = grant.materializations.find(
      (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
    );
    if (current?.state === "installed") {
      if (current.account === binding.account && current.permissionId === binding.permissionId)
        return;
      return clientFail(
        "oaath_client_state_conflict",
        "installed Grant materialization has another binding",
        "grant_materialization_binding_mismatch",
      );
    }
    if (current?.state !== "installing") return;
    if (current.account !== binding.account || current.permissionId !== binding.permissionId) {
      return clientFail(
        "oaath_client_state_conflict",
        "installing Grant materialization has another binding",
        "grant_materialization_binding_mismatch",
      );
    }
    if (current.operationId !== value.identity.userOperationHash) {
      return clientFail(
        "oaath_client_state_conflict",
        "installing Grant materialization belongs to another operation",
        "grant_materialization_operation_mismatch",
      );
    }
    try {
      await commit(
        snapshot,
        transition(grant, {
          type: "record_installed",
          identity: grant.identity,
          binding,
          operationId: value.identity.userOperationHash,
          installation: {
            ...binding,
            kind: "permission_present",
            blockNumber: value.finality.blockNumber,
            blockHash: value.finality.blockHash,
            observedAt: value.finality.observedAt,
          },
        }),
      );
    } catch (error) {
      const retained = await refresh().catch(() => {
        throw error;
      });
      const installed = retained.value.materializations.find(
        (entry) => entry.chainId === binding.chainId && entry.state === "installed",
      );
      if (
        installed?.state === "installed" &&
        installed.account === binding.account &&
        installed.permissionId === binding.permissionId
      ) {
        return;
      }
      throw error;
    }
  }

  async function recordRecoveredMaterialization(
    account: `0x${string}`,
    result: OperationObserveResult,
  ): Promise<void> {
    if (result.status !== "observed" || result.record.value.state !== "finalized") {
      return;
    }
    const chainId = result.record.value.identity.chainId;
    const grant = (await refresh()).value;
    const installing = grant.materializations.find(
      (entry) => entry.chainId === chainId && entry.state === "installing",
    );
    if (installing?.state !== "installing") return;
    if (installing.account !== account) {
      return clientFail(
        "oaath_client_state_conflict",
        "recovered installation belongs to another account",
        "grant_materialization_operation_mismatch",
      );
    }
    await recordFinalizedMaterialization(
      Object.freeze({
        chainId,
        account,
        permissionId: installing.permissionId,
      }),
      result,
    );
  }

  function requireMaterializationOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    operation: OaathProviderOperationPointer,
  ): `0x${string}` {
    const identity = operation.identity;
    if (
      identity.kind !== "execution" ||
      identity.grantId !== record.value.identity.grantId ||
      identity.chainId !== binding.chainId ||
      identity.account !== binding.account
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the operation does not match its Grant materialization",
        "grant_materialization_operation_mismatch",
      );
    }
    return identity.userOperationHash;
  }

  async function authorizeExecutionOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    mode: "standard" | "enable-replayable",
    operation: OaathProviderOperationPointer,
  ): Promise<void> {
    const operationId = requireMaterializationOperation(binding, operation);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      requireExecutionPublication();
      const snapshot = await requireActive();
      const current = snapshot.value.materializations.find(
        (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
      );
      if (
        !current ||
        current.state === "unsupported" ||
        current.account !== binding.account ||
        current.permissionId !== binding.permissionId
      ) {
        return clientFail(
          "oaath_client_state_conflict",
          "the Grant materialization binding changed before signing",
          "grant_materialization_binding_mismatch",
        );
      }

      if (mode === "enable-replayable") {
        if (current.state === "installing" && current.operationId === operationId) {
          // Another exact producer already admitted this same operation. Its
          // begin-materialization CAS is the shared linearization point.
          return;
        }
        if (current.state !== "unmaterialized") {
          return clientFail(
            "oaath_client_state_conflict",
            "another operation owns Grant materialization",
            "grant_materialization_operation_mismatch",
          );
        }
        try {
          await commit(
            snapshot,
            transition(snapshot.value, {
              type: "begin_materialization",
              identity: snapshot.value.identity,
              binding,
              operationId,
              startedAt: input.now(),
            }),
          );
          return;
        } catch (error) {
          if (
            error instanceof OaathClientError &&
            error.source === "grant_store_conflict" &&
            attempt < 2
          ) {
            continue;
          }
          throw error;
        }
      }

      if (current.state !== "installed") {
        return clientFail(
          "oaath_client_state_conflict",
          "the Grant permission is not installed",
          "grant_materialization_not_installed",
        );
      }
      // Even when the aggregate value is unchanged, this CAS is the durable
      // admission linearization point against another handle beginning revocation.
      try {
        await commit(snapshot, snapshot.value);
        return;
      } catch (error) {
        if (
          error instanceof OaathClientError &&
          error.source === "grant_store_conflict" &&
          attempt < 2
        ) {
          continue;
        }
        throw error;
      }
    }
    return clientFail(
      "oaath_client_state_conflict",
      "the Grant could not admit the exact operation",
      "grant_store_conflict",
    );
  }

  function materializationReleaseTime(grant: Grant): number {
    const observedAt = input.now();
    return grant.state === "active"
      ? Math.min(Math.max(observedAt, grant.updatedAt), grant.expiresAt - 1)
      : Math.max(observedAt, grant.updatedAt);
  }

  async function abandonExecutionOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    mode: "standard" | "enable-replayable",
    operation: OaathProviderOperationPointer,
  ): Promise<void> {
    if (mode !== "enable-replayable") return;
    const operationId = requireMaterializationOperation(binding, operation);
    const snapshot = await refresh();
    const grant = snapshot.value;
    if (grant.state !== "active" && grant.state !== "revoking") return;
    const current = grant.materializations.find(
      (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
    );
    if (
      current?.state !== "installing" ||
      current.account !== binding.account ||
      current.permissionId !== binding.permissionId ||
      current.operationId !== operationId
    ) {
      return;
    }
    const abandonedAt = materializationReleaseTime(grant);
    await commit(
      snapshot,
      transition(grant, {
        type: "abandon_materialization",
        identity: grant.identity,
        binding,
        operationId,
        abandonedAt,
      }),
    );
  }

  async function reconcileInstallingMaterialization(
    snapshot: GrantStoreRecord,
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    operationId: `0x${string}`,
    observeUnresolved = false,
  ): Promise<GrantStoreRecord> {
    const operationKey = Object.freeze({
      grantId: snapshot.value.identity.grantId,
      chainId: binding.chainId,
      kind: "execution" as const,
    });
    let operation = await exactOperation(operationKey, operationId);
    if (
      observeUnresolved &&
      (operation?.value.state === "prepared" ||
        operation?.value.state === "submission_attempted" ||
        operation?.value.state === "submitted" ||
        operation?.value.state === "included")
    ) {
      const observing = observationOnlyRunner(binding.chainId);
      try {
        const observedAt = Math.max(input.now(), operation.value.updatedAt);
        if (operation.value.state === "prepared") {
          await observing.abandonPreparedOperation({
            kind: "execution",
            key: operationKey,
            expectedUserOperationHash: operationId,
            abandonedAt: observedAt,
          });
        } else {
          await observing.observeOperation({
            kind: "execution",
            key: operationKey,
            preparedAt: observedAt,
            attemptedAt: observedAt,
            submittedAt: observedAt,
            observedAt,
            timeoutMs: SUBMISSION_TIMEOUT_MS,
            expectedUserOperationHash: operationId,
          });
        }
      } finally {
        await observing.close().catch(() => undefined);
      }
      operation = await exactOperation(operationKey, operationId);
    }
    if (
      operation === undefined ||
      operation.value.identity.account !== binding.account ||
      operation.value.identity.userOperationHash !== operationId
    ) {
      return snapshot;
    }
    if (operation.value.state === "finalized") {
      return commit(
        snapshot,
        transition(snapshot.value, {
          type: "record_installed",
          identity: snapshot.value.identity,
          binding,
          operationId,
          installation: {
            ...binding,
            kind: "permission_present",
            blockNumber: operation.value.finality.blockNumber,
            blockHash: operation.value.finality.blockHash,
            observedAt: operation.value.finality.observedAt,
          },
        }),
      );
    }
    if (operation.value.state === "superseded") {
      const observation = await observeChainPermission(binding, {
        installedAtBlock: null,
        notBefore: {
          blockNumber: operation.value.supersession.blockNumber,
          blockHash: operation.value.supersession.blockHash,
        },
      });
      if (observation?.status === "present") {
        return commit(
          snapshot,
          transition(snapshot.value, {
            type: "record_installed",
            identity: snapshot.value.identity,
            binding,
            operationId,
            installation: observation.installation,
          }),
        );
      }
      if (observation?.status !== "absent") return snapshot;
      return commit(
        snapshot,
        transition(snapshot.value, {
          type: "abandon_materialization",
          identity: snapshot.value.identity,
          binding,
          operationId,
          abandonedAt: observation.removal.observedAt,
        }),
      );
    }
    const conclusivelyNotInstalled =
      operation.value.state === "abandoned" ||
      (operation.value.state === "dropped" && operation.value.priorInclusion === null);
    if (!conclusivelyNotInstalled) return snapshot;
    return commit(
      snapshot,
      transition(snapshot.value, {
        type: "abandon_materialization",
        identity: snapshot.value.identity,
        binding,
        operationId,
        abandonedAt: materializationReleaseTime(snapshot.value),
      }),
    );
  }

  async function authorizeRevocationOperation(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    operation: OaathProviderOperationPointer,
  ): Promise<void> {
    const identity = operation.identity;
    if (
      identity.kind !== "revocation" ||
      identity.grantId !== record.value.identity.grantId ||
      identity.chainId !== binding.chainId ||
      identity.account !== binding.account
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the revocation operation does not match its Grant materialization",
        "grant_materialization_operation_mismatch",
      );
    }
    const snapshot = await refresh();
    const grant = snapshot.value;
    const current = grant.materializations.find(
      (entry) => entry.chainId === binding.chainId && entry.state !== "unsupported",
    );
    if (
      grant.state !== "revoking" ||
      !(
        (current?.state === "revoking" &&
          current.account === binding.account &&
          current.permissionId === binding.permissionId) ||
        (input.installApproval?.version === OAATH_KERNEL_V33_APPROVAL_VERSION &&
          (current === undefined || current.state === "unmaterialized") &&
          grant.revocation?.targets.some(
            (target) =>
              target.chainId === binding.chainId &&
              target.account === binding.account &&
              target.permissionId === binding.permissionId,
          ) &&
          !grant.revocation.evidence.some((proof) => proof.permission.chainId === binding.chainId))
      )
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "the Grant no longer admits this revocation operation",
        "grant_materialization_binding_mismatch",
      );
    }
    await commit(snapshot, grant);
  }

  async function executeCalls(
    value: unknown,
    requestHash: `0x${string}` | null,
    publication?: Readonly<OaathProviderOperationPublication>,
    paymaster: Readonly<
      | {
          readonly kind: "erc7677";
          readonly sponsorship: OaathKernelSponsorshipCapability;
          readonly resultCapabilities: () => Readonly<OaathWalletCallResultCapabilities> | null;
        }
      | { readonly kind: "erc7902-static"; readonly paymaster: PreparedPaymaster }
    > | null = null,
    validityAdmission: Readonly<ValidityAdmissionEvidence> | null = null,
    executionRouteAdmission: Readonly<ExecutionRouteAdmissionEvidence> | null = null,
    connectedFeePayer: Readonly<ConnectedEoa> | null = null,
  ): Promise<Readonly<OaathOperationHandle>> {
    const context: CaptureContext = new WeakSet();
    const request = exactClientRecord(value, ["chain", "calls"], "sendCalls input", context);
    const chainId = request.chain;
    if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
      return clientFail("oaath_client_input_invalid", "sendCalls chain is invalid");
    }
    const calls = captureCalls(request.calls, context);
    const resolved = await resolveExecutionShape(
      chainId,
      calls,
      validityAdmission,
      executionRouteAdmission,
    );
    if (paymaster !== null && resolved.decision.route !== "bundler") {
      return clientFail(
        "oaath_client_capability_unsupported",
        "paymaster sponsorship requires the bundler route",
        `${paymaster.kind}_bundler_unavailable`,
      );
    }
    if (connectedFeePayer !== null && resolved.decision.route !== "bundler")
      return clientFail(
        "oaath_client_capability_unsupported",
        "connected fee payer requires the initial bundler route",
      );
    const key = Object.freeze({
      grantId: resolved.grantId,
      chainId,
      kind: "execution" as const,
    });

    const shape = {
      chainId,
      kind: "execution" as const,
      runtime: resolved.runtime,
      descriptor: resolved.descriptor,
      calls,
      signer: "session" as const,
      mode: resolved.mode,
      materializer: resolved.materializer,
      decision: resolved.decision,
      grantId: resolved.grantId,
      requestHash,
      ...(resolved.validityTimeRange === undefined
        ? {}
        : { validityTimeRange: resolved.validityTimeRange }),
      authorizeOperation: (operation: OaathProviderOperationPointer) =>
        authorizeExecutionOperation(resolved.binding, resolved.mode, operation),
      abandonOperation: (operation: OaathProviderOperationPointer) =>
        abandonExecutionOperation(resolved.binding, resolved.mode, operation),
    };
    // The sender may replace a terminal lane, while the returned handle receives
    // a separate read-only runner and pins the exact hash below. Neither can
    // submit twice for one identity.
    const sender = runner({
      ...shape,
      connectedFeePayer,
      terminalBehavior: "replace",
      ...(publication ? { publication } : {}),
      ...(paymaster?.kind === "erc7677"
        ? {
            sponsorship: paymaster.sponsorship,
            sponsorshipResultCapabilities: paymaster.resultCapabilities,
          }
        : {}),
      ...(paymaster?.kind === "erc7902-static" ? { staticPaymaster: paymaster.paymaster } : {}),
    });
    let result: OperationStartResult;
    try {
      result = await startOnce(sender, "execution", key);
    } finally {
      // A cleanup failure never replaces the outcome of the send.
      await sender.close().catch(() => undefined);
    }
    // Raises a state conflict before any handle exists to leak.
    operationOutcome(result);
    return trackedOperationHandle({
      runner: runner({ ...shape, terminalBehavior: "reuse_same_kind" }),
      key,
      kind: "execution",
      timeoutMs: SUBMISSION_TIMEOUT_MS,
      now: input.now,
      initial: result,
      observation: (readRequest) => resolved.chain.observation.read(readRequest),
      ...(resolved.mode === "enable-replayable"
        ? {
            onObserved: (observed: OperationObserveResult) =>
              recordFinalizedMaterialization(resolved.binding, observed),
          }
        : {}),
    });
  }

  function approvedExternalKey(value: Readonly<OaathExternalPreparedCallKey>): void {
    if (value.prehash !== false || typeof value.publicKey !== "string") {
      clientFail("oaath_client_input_invalid", "prepared-call key is invalid");
    }
    const approved = input.binding.operatorCredential;
    if (value.type === "secp256k1" && approved.kind === "ecdsa") {
      let address: string;
      try {
        address = publicKeyToAddress(value.publicKey).toLowerCase();
      } catch {
        clientFail("oaath_client_input_invalid", "prepared-call public key is invalid");
      }
      if (address === approved.address && input.sessionKey.kind === "ecdsa") return;
    }
    if (
      value.type === "webauthn-p256" &&
      approved.kind === "webauthn" &&
      input.sessionKey.kind === "webauthn" &&
      value.publicKey === approved.publicKey
    ) {
      return;
    }
    clientFail(
      "oaath_client_capability_invalid",
      "prepared-call key is not the approved operator credential",
      "operator_credential_mismatch",
    );
  }

  function preparedCustody(): Readonly<OaathExternalPreparedCallPlan["custody"]> {
    const signer = input.request.sessionSigner;
    if (signer === null) return Object.freeze({ mode: "frontend", providerId: null });
    if (signer.mode === "application_backend") {
      return Object.freeze({ mode: signer.mode, providerId: signer.providerId });
    }
    return unsupported("prepared_calls_hosted_custody_unsupported");
  }

  function storedGas(
    prepared: Readonly<PreparedUserOperation>,
  ): Readonly<KernelV4UserOperationGas> {
    const operation = prepared.userOperation;
    return Object.freeze({
      callGasLimit: operation.callGasLimit,
      verificationGasLimit: operation.verificationGasLimit,
      preVerificationGas: operation.preVerificationGas,
      maxFeePerGas: operation.maxFeePerGas,
      maxPriorityFeePerGas: operation.maxPriorityFeePerGas,
    });
  }

  function sameFeePayer(
    left: Readonly<OaathFeePayerDescriptor> | null,
    right: Readonly<OaathFeePayerDescriptor> | null,
  ): boolean {
    return (
      (left === null && right === null) ||
      (left !== null &&
        right !== null &&
        left.address === right.address &&
        left.balance === right.balance)
    );
  }

  function samePreparedCalls(
    left: readonly Readonly<OaathCallInput>[],
    right: readonly Readonly<KernelV4Call>[],
  ): boolean {
    return (
      left.length === right.length &&
      left.every((call, index) => {
        const retained = right[index];
        return (
          retained !== undefined &&
          call.target === retained.target &&
          call.value === retained.value &&
          call.data === retained.data
        );
      })
    );
  }

  function externalPlan(
    shape: Readonly<ExecutionShape>,
    key: Readonly<OaathExternalPreparedCallKey>,
    custody: Readonly<OaathExternalPreparedCallPlan["custody"]>,
    result: Awaited<ReturnType<typeof prepareExecutionShape>>,
  ): Readonly<OaathExternalPreparedCallPlan> {
    return Object.freeze({
      grantId: shape.grantId,
      account: shape.descriptor.account,
      chainId: shape.chainId,
      calls: Object.freeze(
        shape.calls.map((call) =>
          Object.freeze({ target: call.target, value: call.value, data: call.data }),
        ),
      ),
      key: Object.freeze({ ...key }),
      custody,
      materialization: Object.freeze({
        mode: shape.mode,
        permissionId: shape.binding.permissionId,
      }),
      quote: result.quote,
      decision: Object.freeze({
        route: shape.decision.route === "bundler" ? ("bundler" as const) : ("direct" as const),
        feePayer: shape.decision.feePayer,
      }),
      resultCapabilities: result.resultCapabilities,
      prepared: result.prepared,
      validityTimeRange: shape.validityTimeRange ?? null,
      expiresAt: shape.grantExpiresAt,
    });
  }

  async function prepareCallsWork(
    value: unknown,
  ): Promise<Readonly<OaathExternalPreparedCallPlan>> {
    if (input.binding.account.kernelVersion === "0.3.3")
      return unsupported("kernel_v33_external_prepared_calls_unsupported");
    const context: CaptureContext = new WeakSet();
    const invalidInput = (message: string): never =>
      clientFail("oaath_client_input_invalid", message);
    const captured = captureRecord(value, "provider prepareCalls input", context, invalidInput);
    const hasValidityAdmission = Object.hasOwn(captured, "validityAdmission");
    const hasExecutionRouteAdmission = Object.hasOwn(captured, "executionRouteAdmission");
    const keys = ["chain", "calls", "key", "paymaster"];
    if (hasValidityAdmission) keys.push("validityAdmission");
    if (hasExecutionRouteAdmission) keys.push("executionRouteAdmission");
    const request = exactCapturedRecord(
      captured,
      keys,
      "provider prepareCalls input",
      invalidInput,
    );
    if (
      typeof request.chain !== "number" ||
      !Number.isSafeInteger(request.chain) ||
      request.chain < 1
    ) {
      return clientFail("oaath_client_input_invalid", "prepared-call chain is invalid");
    }
    const validityAdmission = hasValidityAdmission
      ? consumeValidityAdmission(request.validityAdmission, request.chain)
      : null;
    const executionRouteAdmission = hasExecutionRouteAdmission
      ? consumeExecutionRouteAdmission(request.executionRouteAdmission, request.chain)
      : null;
    const keyRecord = exactClientRecord(
      request.key,
      ["type", "publicKey", "prehash"],
      "provider prepared-call key",
      context,
    );
    const key = Object.freeze({
      type: keyRecord.type,
      publicKey: keyRecord.publicKey,
      prehash: keyRecord.prehash,
    }) as Readonly<OaathExternalPreparedCallKey>;
    approvedExternalKey(key);
    const custody = preparedCustody();
    const calls = captureCalls(request.calls, context);
    const paymaster = providerPaymaster(request.chain, request.paymaster, context);
    if (paymaster?.kind === "erc7902-static") {
      return unsupported("prepared_calls_static_paymaster_unsupported");
    }
    const shape = await resolveExecutionShape(
      request.chain,
      calls,
      validityAdmission,
      executionRouteAdmission,
    );
    if (paymaster !== null && shape.decision.route !== "bundler") {
      return unsupported("erc7677_bundler_unavailable");
    }
    return externalPlan(
      shape,
      key,
      custody,
      await prepareExecutionShape(shape, {
        paymaster:
          paymaster === null
            ? null
            : Object.freeze({
                kind: "resolve-erc7677" as const,
                sponsorship: paymaster.sponsorship,
                resultCapabilities: paymaster.resultCapabilities,
              }),
      }),
    );
  }

  async function validatePreparedCallsWork(
    value: Readonly<{
      plan: Readonly<OaathExternalPreparedCallPlan>;
      signature: `0x${string}`;
    }>,
  ): Promise<Readonly<OaathValidatedPreparedCalls>> {
    const plan = value.plan;
    approvedExternalKey(plan.key);
    const custody = preparedCustody();
    if (
      plan.grantId !== record.value.identity.grantId ||
      plan.custody.mode !== custody.mode ||
      plan.custody.providerId !== custody.providerId
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "prepared-call authority changed",
        "prepared_call_authority_changed",
      );
    }
    const calls = captureCalls(plan.calls, new WeakSet());
    const retainedValidityTimeRange = plan.validityTimeRange;
    let validityEvidence: Readonly<ValidityAdmissionEvidence> | null = null;
    if (retainedValidityTimeRange !== null) {
      try {
        validityEvidence = await proveValidityTimeRange({
          chain: plan.chainId,
          range: retainedValidityTimeRange,
        });
      } catch {
        validityEvidence = null;
      }
      if (validityEvidence === null) {
        return clientFail(
          "oaath_client_state_conflict",
          "prepared-call validity evidence is stale",
          "prepared_call_stale",
        );
      }
    }
    const shape = await resolveExecutionShape(plan.chainId, calls, validityEvidence);
    const retainedPaymaster = plan.prepared.userOperation.paymaster;
    const current = await prepareExecutionShape(shape, {
      gas: storedGas(plan.prepared),
      paymaster:
        retainedPaymaster === null
          ? null
          : Object.freeze({ kind: "retained" as const, paymaster: retainedPaymaster }),
    });
    const expectedRoute = shape.decision.route === "bundler" ? "bundler" : "direct";
    if (
      plan.account !== shape.descriptor.account ||
      plan.expiresAt > shape.grantExpiresAt ||
      !samePreparedCalls(plan.calls, shape.calls) ||
      plan.materialization.mode !== shape.mode ||
      plan.materialization.permissionId !== shape.binding.permissionId ||
      plan.quote.nonceKey !== current.quote.nonceKey ||
      plan.quote.sequence !== current.quote.sequence ||
      plan.decision.route !== expectedRoute ||
      !sameFeePayer(plan.decision.feePayer, shape.decision.feePayer) ||
      (retainedPaymaster !== null &&
        (plan.decision.route !== "bundler" || expectedRoute !== "bundler")) ||
      current.prepared.userOperationHash !== plan.prepared.userOperationHash
    ) {
      return clientFail(
        "oaath_client_state_conflict",
        "prepared-call context is stale",
        "prepared_call_stale",
      );
    }
    const signature = await finalExternalSignature(shape, plan.prepared, value.signature);
    const validated: Readonly<OaathValidatedPreparedCalls> = Object.freeze({ plan });
    validatedPreparedCalls.set(validated, Object.freeze({ shape, plan, signature }));
    return validated;
  }

  async function startPreparedCallsWork(
    validated: Readonly<OaathValidatedPreparedCalls>,
    requestHash: `0x${string}`,
    publicationValue: OaathProviderOperationPublication,
  ): Promise<Readonly<OaathOperationHandle>> {
    const retained = validatedPreparedCalls.get(validated);
    if (!retained || !USER_OPERATION_HASH.test(requestHash)) {
      return clientFail(
        "oaath_client_capability_invalid",
        "validated prepared-call capability is invalid",
      );
    }
    const publication = captureProviderPublication(publicationValue);
    const { shape, plan, signature } = retained;
    const key = Object.freeze({
      grantId: shape.grantId,
      chainId: shape.chainId,
      kind: "execution" as const,
    });
    const runnerShape = {
      chainId: shape.chainId,
      kind: "execution" as const,
      runtime: shape.runtime,
      descriptor: shape.descriptor,
      calls: shape.calls,
      signer: "session" as const,
      mode: shape.mode,
      materializer: shape.materializer,
      decision: shape.decision,
      grantId: shape.grantId,
      requestHash,
      prepared: plan.prepared,
      preparedResultCapabilities: plan.resultCapabilities,
      externalSignature: signature,
      authorizeOperation: (operation: OaathProviderOperationPointer) =>
        authorizeExecutionOperation(shape.binding, shape.mode, operation),
      abandonOperation: (operation: OaathProviderOperationPointer) =>
        abandonExecutionOperation(shape.binding, shape.mode, operation),
    };
    const sender = runner({
      ...runnerShape,
      terminalBehavior: "replace",
      publication,
    });
    let result: OperationStartResult;
    try {
      result = await resumePreparedOnce(sender, key, plan.prepared.userOperationHash);
    } finally {
      await sender.close().catch(() => undefined);
    }
    operationOutcome(result);
    return trackedOperationHandle({
      runner: runner({ ...runnerShape, terminalBehavior: "reuse_same_kind" }),
      key,
      kind: "execution",
      timeoutMs: SUBMISSION_TIMEOUT_MS,
      now: input.now,
      initial: result,
      observation: shape.chain.observation.read,
      ...(shape.mode === "enable-replayable"
        ? {
            onObserved: (observed: OperationObserveResult) =>
              recordFinalizedMaterialization(shape.binding, observed),
          }
        : {}),
    });
  }

  function autoSelection(requested: "auto" | "session" | undefined) {
    // Every accepted plain call bundle is encoded atomically into one UserOp.
    // Unsupported sizes/encodings fail before effects; this API never splits a bundle.
    return requested === "auto"
      ? selectAutoSigner(!credentialKeyIsReadOnly(input.ownerKey), true)
      : null;
  }

  async function resolveAutoOwnerRead(chainId: number, calls: readonly Readonly<KernelV4Call>[]) {
    requireExecutionPublication();
    const grantSnapshot = await requireActive();
    const chain = chainCapability(chainId);
    requireKernelCapability(chainId, kernelKeyCapability("owner", input.ownerKey.kind));
    const runtime = ownerRuntime(chainId);
    const descriptor = await accountDescriptor(chainId, runtime);
    const shape = {
      chainId,
      kind: "execution" as const,
      signer: "owner" as const,
      grantId: grantSnapshot.value.identity.grantId,
      runtime,
      descriptor,
      calls,
      materializer: null,
      mode: "standard" as const,
    };
    // Runtime-owned preparation proves the whole call bundle fits its atomic encoding.
    // This zero-gas simulation is neither quoted, persisted nor signed.
    quoteRequest(shape, null, "estimate");
    const bundler = await classifiedBundler(chainId, chain, runtime.deployment.entryPoint.address);
    const routed = decideExecution({
      operationKind: "execution",
      signer: "owner",
      sessionCoverage: "unreadable",
      bundler,
      feePayer: chain.feePayer,
    });
    if (routed.route === "none")
      return clientFail(
        "oaath_client_route_unavailable",
        "no safe submission route is available",
        routed.reasons.join(","),
      );
    const decision = Object.freeze({
      ...routed,
      reasons: Object.freeze([
        "owner_auto_single_operation" as const,
        ...routed.reasons.filter((reason) => reason !== "owner_explicit"),
      ]),
    });
    requireExecutionPublication();
    return { ...shape, grantSnapshot, chain, decision };
  }

  function requirePlainRoute(
    route: OaathExecutionRoute,
    sponsored: boolean,
    connectedFeePayer: Readonly<ConnectedEoa> | null,
  ) {
    if (route !== "bundler" && (sponsored || connectedFeePayer !== null))
      return clientFail(
        "oaath_client_capability_unsupported",
        "plain sponsorship and connected fee payer require the initial bundler route",
      );
  }

  async function executeAutoOwnerCalls(
    chainId: number,
    calls: readonly Readonly<KernelV4Call>[],
    sponsorship: ReturnType<typeof capturePaymasterService> | null,
    connectedFeePayer: Readonly<ConnectedEoa> | null,
  ): Promise<Readonly<OaathOperationHandle>> {
    const resolved = await resolveAutoOwnerRead(chainId, calls);
    requirePlainRoute(resolved.decision.route, sponsorship !== null, connectedFeePayer);
    const key = Object.freeze({ grantId: resolved.grantId, chainId, kind: "execution" as const });
    const sender = runner({
      ...resolved,
      requestHash: null,
      connectedFeePayer,
      terminalBehavior: "replace",
      ...(sponsorship === null
        ? {}
        : {
            sponsorship,
            sponsorshipResultCapabilities: () =>
              readCompletedErc7677ResultCapabilities(sponsorship),
          }),
      async authorizeOperation(operation) {
        requireExecutionPublication();
        const identity = operation.identity;
        if (
          identity.kind !== "execution" ||
          identity.grantId !== resolved.grantId ||
          identity.chainId !== chainId ||
          identity.account !== resolved.descriptor.account
        )
          return clientFail(
            "oaath_client_state_conflict",
            "owner operation does not match its Grant/account",
          );
        const snapshot = await requireActive();
        // Admit against revocation with the same durable CAS used for session sends.
        // Root execution does not install or advance a session materialization.
        await commit(snapshot, snapshot.value);
      },
    });
    let result: OperationStartResult;
    try {
      result = await startOnce(sender, "execution", key);
    } finally {
      await sender.close().catch(() => undefined);
    }
    operationOutcome(result);
    return trackedOperationHandle({
      runner: observationOnlyRunner(chainId),
      key,
      kind: "execution",
      timeoutMs: SUBMISSION_TIMEOUT_MS,
      now: input.now,
      initial: result,
      observation: resolved.chain.observation.read,
    });
  }

  function sendCalls(value: unknown): Promise<Readonly<OaathOperationHandle>> {
    return withExecution(() => {
      const context: CaptureContext = new WeakSet();
      const request = capturePlainCalls(value, context, true);
      const connectedFeePayer = Object.hasOwn(request, "feePayer")
        ? captureConnectedEoa(request.feePayer, context)
        : null;
      const sponsorship = Object.hasOwn(request, "paymasterService")
        ? capturePaymasterService(
            request.paymasterService,
            chainCapability(request.chain).paymasterService,
            context,
          )
        : null;
      if (autoSelection(request.signer)?.signer === "owner")
        return executeAutoOwnerCalls(
          request.chain,
          captureCalls(request.calls, context),
          sponsorship,
          connectedFeePayer,
        );
      return executeCalls(
        { chain: request.chain, calls: request.calls },
        null,
        undefined,
        sponsorship === null
          ? null
          : {
              kind: "erc7677",
              sponsorship,
              resultCapabilities: () => readCompletedErc7677ResultCapabilities(sponsorship),
            },
        null,
        null,
        connectedFeePayer,
      );
    });
  }

  function reviewCalls(value: unknown): Promise<Readonly<OaathCallsReview>> {
    return withActivity(async () => {
      const context: CaptureContext = new WeakSet();
      const request = capturePlainCalls(value, context, true);
      const connectedFeePayer = Object.hasOwn(request, "feePayer")
        ? captureConnectedEoa(request.feePayer, context)
        : null;
      const chainId = request.chain;
      if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
        return clientFail("oaath_client_input_invalid", "reviewCalls chain is invalid");
      }
      const calls = captureCalls(request.calls, context);
      const selectedPaymaster = Object.hasOwn(request, "paymasterService")
        ? capturePaymasterService(
            request.paymasterService,
            chainCapability(chainId).paymasterService,
            context,
          )
        : null;
      requireExecutionPublication();
      const selection = autoSelection(request.signer);
      if (selection?.signer === "owner") {
        const resolved = await resolveAutoOwnerRead(chainId, calls);
        requirePlainRoute(resolved.decision.route, selectedPaymaster !== null, connectedFeePayer);
        const current = await requireActive();
        if (current.storeRevision !== resolved.grantSnapshot.storeRevision)
          return clientFail(
            "oaath_client_state_conflict",
            "the Grant changed during execution review",
            "grant_store_conflict",
          );
        requireExecutionPublication();
        return Object.freeze({
          grantId: resolved.grantId,
          chainId,
          accountId: input.binding.context.accountId,
          account: resolved.descriptor.account,
          calls,
          signer: "owner" as const,
          route: resolved.decision.route as "bundler" | "entrypoint-handleops",
          reasons: resolved.decision.reasons,
          fallback: connectedEoaReview(connectedFeePayer),
          paymasterService:
            selectedPaymaster === null
              ? null
              : Object.freeze({ url: chainCapability(chainId).paymasterService!.url }),
          enableVerificationGasFloor: null,
          enforcement: Object.freeze({
            calls: "none" as const,
            expiry: "client" as const,
            operationCount: "none" as const,
          }),
          expiresAt: current.value.expiresAt,
          validAfter: null,
          validUntil: null,
          perChainOperationLimit: null,
        });
      }
      const resolved = await resolveExecutionRead(chainId, calls);
      requireExecutionPublication();
      const current = await requireActive();
      if (current.storeRevision !== resolved.grantSnapshot.storeRevision) {
        return clientFail(
          "oaath_client_state_conflict",
          "the Grant changed during execution review",
          "grant_store_conflict",
        );
      }
      const materialization = current.value.materializations.find(
        (entry) => entry.chainId === chainId && entry.state !== "unsupported",
      );
      if (materialization?.state !== "installed") {
        if (
          materialization !== undefined &&
          materialization.state !== "unmaterialized" &&
          materialization.state !== "installing"
        ) {
          return unsupported(`grant_materialization_${materialization.state}`);
        }
        // Binding checks the retained approval without materializing or persisting it.
        permissionMaterializer(resolved.runtime, resolved.descriptor.account);
      }
      const { route, signer } = resolved.decision;
      if (connectedFeePayer !== null && route !== "bundler")
        return clientFail(
          "oaath_client_capability_unsupported",
          "connected fee payer requires the initial bundler route",
        );
      if (selectedPaymaster !== null && route !== "bundler") {
        return clientFail(
          "oaath_client_capability_unsupported",
          "paymaster sponsorship requires the bundler route",
          "erc7677_bundler_unavailable",
        );
      }
      const policy = input.approvedPolicy;
      if (route === "none" || signer !== "session" || policy.validUntil === null) {
        return unsupported("execution_review_unavailable");
      }
      requireExecutionPublication();
      return Object.freeze({
        grantId: current.value.identity.grantId,
        fallback: connectedEoaReview(connectedFeePayer),
        paymasterService:
          selectedPaymaster === null
            ? null
            : Object.freeze({ url: chainCapability(chainId).paymasterService!.url }),
        chainId,
        accountId: input.binding.context.accountId,
        account: resolved.descriptor.account,
        calls,
        signer,
        route,
        reasons:
          selection === null
            ? resolved.decision.reasons
            : Object.freeze([selection.reason, ...resolved.decision.reasons]),
        enableVerificationGasFloor:
          materialization?.state !== "installed" &&
          resolved.runtime.gasPolicy.enableVerificationGasFloor > 0n
            ? resolved.runtime.gasPolicy.enableVerificationGasFloor.toString(10)
            : null,
        enforcement: Object.freeze({
          calls: "onchain" as const,
          expiry: "onchain" as const,
          operationCount: "onchain" as const,
        }),
        expiresAt: current.value.expiresAt,
        validAfter: policy.validAfter,
        validUntil: policy.validUntil,
        perChainOperationLimit: policy.perChainOperationLimit,
      });
    });
  }

  function getOperation(value: unknown): Promise<Readonly<OaathOperationHandle> | null> {
    return withActivity(async () => {
      const request = exactClientRecord(
        value,
        ["chain", "id"],
        "getOperation input",
        new WeakSet(),
      );
      const chainId = request.chain;
      const id = request.id;
      if (
        typeof chainId !== "number" ||
        !Number.isSafeInteger(chainId) ||
        chainId < 1 ||
        typeof id !== "string" ||
        !USER_OPERATION_HASH.test(id)
      ) {
        return clientFail("oaath_client_input_invalid", "getOperation reference is invalid");
      }
      chainCapability(chainId);
      const key = Object.freeze({
        grantId: record.value.identity.grantId,
        chainId,
        kind: "execution" as const,
      });
      const operation = await exactOperation(key, id as `0x${string}`);
      return operation === undefined ? null : observationHandle(key, operation);
    });
  }

  function registeredPaymasterServiceUrl(chainId: number): string | null {
    return chainCapability(chainId).paymasterService?.url ?? null;
  }

  function staticPaymasterConfigurationHash(chainId: number): `0x${string}` | null {
    return chainCapability(chainId).staticPaymasterConfigurationHash;
  }

  function admitExecutionRoute(
    chainId: number,
  ): Promise<Readonly<OaathProviderExecutionRouteAdmissionResult>> {
    return withActivity(async () => {
      if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1) {
        return clientFail("oaath_client_input_invalid", "provider route chain is invalid");
      }
      if (revocationRequested) {
        return clientFail(
          "oaath_client_grant_inactive",
          "the Grant is being revoked",
          "grant_revocation_requested",
        );
      }
      await requireActive();
      const chain = chainCapability(chainId);
      const deployment = (() => {
        try {
          return kernelV4Deployment(chainId);
        } catch (error) {
          return mapClientFailure(error, "chain is not a supported Kernel deployment");
        }
      })();
      const bundler = await classifiedBundler(chainId, chain, deployment.entryPoint.address);
      const admission = Object.freeze({
        kind: "oaath_provider_execution_route_admission" as const,
      });
      executionRouteAdmissions.set(admission, Object.freeze({ chainId, bundler }));
      return Object.freeze({
        sponsorship: supportsBundlerSponsorship(bundler)
          ? ("supported" as const)
          : ("unsupported" as const),
        admission,
      });
    });
  }

  function consumeExecutionRouteAdmission(
    value: unknown,
    chainId: number,
  ): Readonly<ExecutionRouteAdmissionEvidence> {
    if (value === null || typeof value !== "object") {
      return clientFail(
        "oaath_client_capability_invalid",
        "provider execution-route admission is invalid",
      );
    }
    const retained = executionRouteAdmissions.get(value);
    executionRouteAdmissions.delete(value);
    if (retained === undefined || retained.chainId !== chainId) {
      return clientFail(
        "oaath_client_capability_invalid",
        "provider execution-route admission is unavailable",
      );
    }
    return retained;
  }

  function approvedValidityTimeRange(at: number): Readonly<KernelV4ValidityTimeRange> | null {
    const validAfter = input.approvedPolicy.validAfter;
    const validUntil = input.approvedPolicy.validUntil;
    if (
      !Number.isSafeInteger(at) ||
      Object.is(at, -0) ||
      at < 0 ||
      !Number.isSafeInteger(validAfter) ||
      Object.is(validAfter, -0) ||
      validAfter < 0 ||
      validUntil === null ||
      !Number.isSafeInteger(validUntil) ||
      Object.is(validUntil, -0) ||
      validUntil < 1 ||
      BigInt(validAfter) > MAX_UINT48 ||
      BigInt(validUntil) > MAX_UINT48 ||
      validAfter >= validUntil ||
      at > validUntil
    ) {
      return null;
    }
    return Object.freeze({
      validAfter: validAfter.toString(10),
      validUntil: validUntil.toString(10),
    });
  }

  async function proveValidityTimeRange(
    value: Readonly<{
      chain: number;
      range: Readonly<KernelV4ValidityTimeRange>;
    }>,
  ): Promise<Readonly<ValidityAdmissionEvidence> | null> {
    const requested = captureProviderValidityAdmissionInput(value);
    if (
      input.binding.account.kernelVersion === "0.3.3" ||
      revocationRequested ||
      !input.chains.has(requested.chain)
    )
      return null;
    try {
      await requireActive();
      const at = input.now();
      const ceiling = approvedValidityTimeRange(at);
      if (ceiling === null) return null;
      const validAfter = BigInt(requested.range.validAfter);
      const validUntil = BigInt(requested.range.validUntil);
      if (
        BigInt(at) > validUntil ||
        validAfter < BigInt(ceiling.validAfter) ||
        validUntil > BigInt(ceiling.validUntil)
      ) {
        return null;
      }
      const runtime = sessionRuntime(requested.chain);
      const descriptor = await accountDescriptor(requested.chain, runtime);
      return Object.freeze({
        chainId: requested.chain,
        range: requested.range,
        runtime,
        descriptor,
      });
    } catch {
      return null;
    }
  }

  function probeValidityTimeRangeSupport(
    chain: number,
  ): Promise<Readonly<OaathProviderValidityTimeRangeSupportResult>> {
    return withActivity(async () => {
      if (
        !Number.isSafeInteger(chain) ||
        chain < 1 ||
        revocationRequested ||
        !input.chains.has(chain)
      ) {
        return unsupportedValidityTimeRange;
      }
      const range = approvedValidityTimeRange(input.now());
      if (range === null) return unsupportedValidityTimeRange;
      const evidence = await proveValidityTimeRange({ chain, range });
      return evidence === null ? unsupportedValidityTimeRange : supportedValidityTimeRange;
    });
  }

  function admitValidityTimeRange(
    value: Readonly<{
      chain: number;
      range: Readonly<KernelV4ValidityTimeRange>;
    }>,
  ): Promise<Readonly<OaathProviderValidityAdmissionResult>> {
    return withActivity(async () => {
      const evidence = await proveValidityTimeRange(value);
      if (evidence === null) return unsupportedValidityAdmission;
      const admission = Object.freeze({
        kind: "oaath_provider_validity_admission" as const,
      });
      validityAdmissions.set(admission, evidence);
      return Object.freeze({ status: "accepted" as const, admission });
    });
  }

  function consumeValidityAdmission(
    value: unknown,
    chainId: number,
  ): Readonly<ValidityAdmissionEvidence> {
    if (value === null || typeof value !== "object") {
      return clientFail(
        "oaath_client_capability_invalid",
        "provider validity admission is invalid",
      );
    }
    const retained = validityAdmissions.get(value);
    validityAdmissions.delete(value);
    if (retained === undefined || retained.chainId !== chainId) {
      return clientFail(
        "oaath_client_capability_invalid",
        "provider validity admission is unavailable",
      );
    }
    return retained;
  }

  function providerSponsorship(
    chainId: number,
    value: unknown,
    context: CaptureContext,
  ): Readonly<OaathKernelSponsorshipCapability> | null {
    if (value === null) return null;
    return capturePaymasterService(value, chainCapability(chainId).paymasterService, context);
  }

  function providerPaymaster(
    chainId: number,
    value: unknown,
    context: CaptureContext,
  ):
    | Readonly<{
        readonly kind: "erc7677";
        readonly sponsorship: OaathKernelSponsorshipCapability;
        readonly resultCapabilities: () => Readonly<OaathWalletCallResultCapabilities> | null;
      }>
    | Readonly<{ readonly kind: "erc7902-static"; readonly paymaster: PreparedPaymaster }>
    | null {
    if (value === null) return null;
    const fail = (message: string): never => clientFail("oaath_client_capability_invalid", message);
    const captured = captureRecord(value, "provider paymaster selection", context, fail);
    if (captured.kind === "erc7677") {
      const selection = exactCapturedRecord(
        captured,
        ["kind", "url", "context"],
        "provider ERC-7677 selection",
        fail,
      );
      const sponsorship = providerSponsorship(
        chainId,
        Object.freeze({ url: selection.url, context: selection.context }),
        context,
      );
      if (sponsorship === null) {
        return clientFail(
          "oaath_client_capability_invalid",
          "provider ERC-7677 selection is empty",
        );
      }
      return Object.freeze({
        kind: "erc7677" as const,
        sponsorship,
        resultCapabilities: () => readCompletedErc7677ResultCapabilities(sponsorship),
      });
    }
    if (captured.kind === "erc7902-static") {
      const selection = exactCapturedRecord(
        captured,
        ["kind", "configuration"],
        "provider ERC-7902 selection",
        fail,
      );
      try {
        const configuration = captureErc7902StaticPaymasterConfiguration(selection.configuration);
        if (
          hashCapturedErc7902PreparedPaymaster(configuration.paymaster) !==
          chainCapability(chainId).staticPaymasterConfigurationHash
        ) {
          return clientFail(
            "oaath_client_capability_invalid",
            "provider ERC-7902 selection does not match the authenticated policy",
            "erc7902_static_policy_mismatch",
          );
        }
        return Object.freeze({
          kind: "erc7902-static" as const,
          paymaster: configuration.paymaster,
        });
      } catch {
        return clientFail(
          "oaath_client_capability_invalid",
          "provider ERC-7902 selection is invalid",
        );
      }
    }
    return clientFail(
      "oaath_client_capability_invalid",
      "provider paymaster selection kind is unsupported",
    );
  }

  function startCalls(
    value: unknown,
    publicationValue: OaathProviderOperationPublication,
  ): Promise<Readonly<OaathOperationHandle>> {
    return withExecution(() => {
      const context: CaptureContext = new WeakSet();
      const invalidInput = (message: string): never =>
        clientFail("oaath_client_input_invalid", message);
      const captured = captureRecord(value, "provider sendCalls input", context, invalidInput);
      const hasValidityAdmission = Object.hasOwn(captured, "validityAdmission");
      const hasExecutionRouteAdmission = Object.hasOwn(captured, "executionRouteAdmission");
      const keys = ["chain", "calls", "requestHash", "paymaster"];
      if (hasValidityAdmission) keys.push("validityAdmission");
      if (hasExecutionRouteAdmission) keys.push("executionRouteAdmission");
      const request = exactCapturedRecord(captured, keys, "provider sendCalls input", invalidInput);
      if (
        typeof request.chain !== "number" ||
        !Number.isSafeInteger(request.chain) ||
        request.chain < 1
      ) {
        return clientFail("oaath_client_input_invalid", "provider chain is invalid");
      }
      const validityAdmission = hasValidityAdmission
        ? consumeValidityAdmission(request.validityAdmission, request.chain)
        : null;
      const executionRouteAdmission = hasExecutionRouteAdmission
        ? consumeExecutionRouteAdmission(request.executionRouteAdmission, request.chain)
        : null;
      if (
        typeof request.requestHash !== "string" ||
        !USER_OPERATION_HASH.test(request.requestHash)
      ) {
        return clientFail(
          "oaath_client_input_invalid",
          "provider request hash must be a lowercase 32-byte hash",
        );
      }
      return executeCalls(
        Object.freeze({ chain: request.chain, calls: request.calls }),
        request.requestHash as `0x${string}`,
        captureProviderPublication(publicationValue),
        providerPaymaster(request.chain, request.paymaster, context),
        validityAdmission,
        executionRouteAdmission,
      );
    });
  }

  function prepareCalls(
    value: Readonly<{
      chain: number;
      calls: readonly Readonly<OaathCallInput>[];
      key: Readonly<OaathExternalPreparedCallKey>;
      paymaster: OaathExternalPreparedCallPaymasterSelection;
      validityAdmission?: Readonly<OaathProviderValidityAdmission>;
      executionRouteAdmission?: Readonly<OaathProviderExecutionRouteAdmission>;
    }>,
  ): Promise<Readonly<OaathExternalPreparedCallPlan>> {
    return withExecution(() => prepareCallsWork(value));
  }

  function validatePreparedCalls(
    value: Readonly<{
      plan: Readonly<OaathExternalPreparedCallPlan>;
      signature: `0x${string}`;
    }>,
  ): Promise<Readonly<OaathValidatedPreparedCalls>> {
    return withExecution(() => validatePreparedCallsWork(value));
  }

  function startPreparedCalls(
    validated: Readonly<OaathValidatedPreparedCalls>,
    requestHash: `0x${string}`,
    publication: OaathProviderOperationPublication,
  ): Promise<Readonly<OaathOperationHandle>> {
    return withExecution(() => startPreparedCallsWork(validated, requestHash, publication));
  }

  function recoverOperation(value: unknown): Promise<Readonly<OaathProviderOperationRecovery>> {
    return withActivity(() => recoverOperationWork(value));
  }

  function abandonPreparedOperation(
    value: unknown,
  ): Promise<Readonly<OaathProviderOperationRecovery>> {
    return withActivity(() => abandonPreparedOperationWork(value));
  }

  async function invalidateCapability(grant: Grant): Promise<Grant> {
    if (grant.approval === null) {
      return clientFail(
        "oaath_client_state_conflict",
        "a revoking Grant has no approval",
        "grant_approval_absent",
      );
    }
    const capabilityHash = grant.approval.capabilityHash;
    let evidence: unknown;
    try {
      evidence = await input.invalidation.invalidateCapability({
        grantId: grant.identity.grantId,
        capabilityHash,
      });
    } catch (error) {
      return mapClientFailure(error, "approval capability invalidation failed");
    }
    const proof = exactClientRecord(
      evidence,
      ["evidenceHash", "invalidatedAt"],
      "capability invalidation evidence",
      new WeakSet(),
      "oaath_client_capability_invalid",
    );
    if (typeof proof.evidenceHash !== "string" || typeof proof.invalidatedAt !== "number") {
      return clientFail(
        "oaath_client_capability_invalid",
        "capability invalidation evidence is invalid",
      );
    }
    // The Grant aggregate owns the exact hash and time rules for the invalidation.
    return transition(grant, {
      type: "record_capability_invalidated",
      identity: grant.identity,
      invalidation: {
        kind: "approval_capability_invalidated",
        capabilityHash,
        evidenceHash: proof.evidenceHash as `0x${string}`,
        invalidatedAt: proof.invalidatedAt,
      },
    });
  }

  /**
   * Finalized-anchored observation via the version's permission-state view.
   * V4 uses isModuleInstalled; v3.3 uses validationConfig/permissionConfig. Absence can
   * complete out-of-band removal; presence can prove a superseded uninstall's
   * effect is still required.
   *
   * Fail closed everywhere: only an exact boolean at a block that rebinds to
   * the same finalized hash counts; every other answer is inconclusive.
   */
  type ChainPermissionObservationFloor =
    | Readonly<{
        installedAtBlock: string;
        notBefore?: Readonly<{ blockNumber: string; blockHash: `0x${string}` }>;
      }>
    | Readonly<{
        installedAtBlock: null;
        notBefore: Readonly<{ blockNumber: string; blockHash: `0x${string}` }>;
      }>;

  async function observeChainPermission(
    binding: Readonly<{ chainId: number; account: `0x${string}`; permissionId: `0x${string}` }>,
    floor: ChainPermissionObservationFloor,
  ): Promise<
    | Readonly<{ status: "present"; installation: Readonly<ChainPermissionEvidence> }>
    | Readonly<{ status: "absent"; removal: Readonly<ChainPermissionEvidence> }>
    | null
  > {
    if (input.installApproval === null) return null;
    const signer = input.installApproval.packages.find((entry) => entry.moduleType === 6)?.module;
    if (signer === undefined) return null;
    try {
      const chain = chainCapability(binding.chainId);
      const finalized = await chain.observation.read({
        type: "finalized_block",
        chainId: binding.chainId,
      });
      const block = finalized as { readonly number?: unknown; readonly hash?: unknown } | null;
      if (
        !block ||
        typeof block.number !== "string" ||
        !/^0x[0-9a-f]+$/u.test(block.number) ||
        typeof block.hash !== "string" ||
        !/^0x[0-9a-f]{64}$/u.test(block.hash)
      ) {
        return null;
      }
      const blockNumber = BigInt(block.number).toString(10);
      // The protocol requires removal evidence to follow the installation; a
      // chain that has not advanced past the install block proves nothing yet.
      if (
        floor.installedAtBlock !== null &&
        BigInt(blockNumber) <= BigInt(floor.installedAtBlock)
      ) {
        return null;
      }
      // Permission presence may only authorize a replacement after the block
      // that proved a superseded uninstall: evidence a lagging provider serves
      // from an earlier block names a chain state the supersession already
      // displaced.
      if (floor.notBefore !== undefined) {
        const fence = BigInt(floor.notBefore.blockNumber);
        const read = BigInt(blockNumber);
        if (read < fence) return null;
        if (read === fence && block.hash !== floor.notBefore.blockHash) return null;
      }
      const installed =
        input.installApproval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
          ? kernelV33PermissionStatus(
              parseKernelV33PermissionState(
                await chain.observation.read({
                  type: "kernel_v33_permission_state",
                  ...binding,
                  blockNumber,
                }),
              ),
              input.installApproval,
            ) === "installed"
          : await chain.observation.read({
              type: "kernel_permission_installed",
              ...binding,
              signer,
              blockNumber,
            });
      if (installed !== true && installed !== false) return null;
      // The read was answered by number alone, so rebind: the block at that
      // number must still be the finalized block this evidence names.
      const rebound = (await chain.observation.read({
        type: "canonical_block",
        chainId: binding.chainId,
        blockNumber,
      })) as { readonly number?: unknown; readonly hash?: unknown } | null;
      if (rebound?.hash !== block.hash || rebound.number !== block.number) return null;
      if (installed) {
        return Object.freeze({
          status: "present" as const,
          installation: Object.freeze({
            ...binding,
            kind: "permission_present" as const,
            blockNumber,
            blockHash: block.hash as `0x${string}`,
            observedAt: input.now(),
          }),
        });
      }
      return Object.freeze({
        status: "absent" as const,
        removal: Object.freeze({
          ...binding,
          kind: "permission_absent" as const,
          blockNumber,
          blockHash: block.hash as `0x${string}`,
          observedAt: input.now(),
        }),
      });
    } catch {
      return null;
    }
  }

  /**
   * Owner-signed removal of one chain's installed permission: the exact
   * reverse-ordered uninstall self-calls, derived from the same install
   * packages the owner's approval bound, run on the chain's revocation lane.
   *
   * A realm that cannot mint or route the owner operation falls back to
   * observation: once the owner's own console has removed the permission, the
   * chain itself proves it and the entry completes. Otherwise the Grant stays
   * durably `revoking` — only finalized success of the uninstall operation or
   * finalized-anchored absence evidence records the chain revoked.
   */
  async function revokeChainPermission(
    snapshot: GrantStoreRecord,
    entry: Grant["materializations"][number],
  ): Promise<GrantStoreRecord> {
    const grant = snapshot.value;
    if (entry.state !== "installed" && entry.state !== "revoking") return snapshot;
    // Without installation evidence there is nothing a removal can be proven
    // against, and without the approval there are no install packages to
    // derive the uninstall calls from.
    if (entry.installation === null || input.installApproval === null) return snapshot;
    const chainId = entry.chainId;
    const binding = Object.freeze({
      chainId,
      account: entry.account,
      permissionId: entry.permissionId,
    });
    let latest = snapshot;
    // Durable intent precedes the probe, the quote, any signature, and any
    // send; a `revoking` entry re-enters here without a second begin.
    if (entry.state === "installed") {
      latest = await commit(
        latest,
        transition(latest.value, {
          type: "begin_chain_revocation",
          identity: latest.value.identity,
          binding,
          startedAt: input.now(),
        }),
      );
    }
    const laneKey = Object.freeze({
      grantId: latest.value.identity.grantId,
      chainId,
      kind: "revocation" as const,
    });
    let value: FinalizedOperation | null = null;
    let prior: OperationStoreRecord | undefined;
    let journalReadable = true;
    const journal = new OperationStore({
      get: (key: Readonly<OperationStoreKey>) => input.operations.get(key),
      getArchived: (value: Parameters<OperationStoreAdapter["getArchived"]>[0]) =>
        input.operations.getArchived(value),
      compareAndSwap: (record: Parameters<OperationStoreAdapter["compareAndSwap"]>[0]) =>
        input.operations.compareAndSwap(record),
      close: async () => undefined,
    });
    try {
      // A prior removal that already finalized successfully completes
      // directly — a Grant commit lost to a crash never mints a second
      // uninstall. The journal must remain readable before any retry decision.
      prior = await journal.get(laneKey);
      if (
        prior !== undefined &&
        prior.value.state === "finalized" &&
        prior.value.inclusion.outcome === "success" &&
        prior.value.identity.account === entry.account
      ) {
        value = prior.value;
      }
    } catch {
      journalReadable = false;
    }
    let permissionObservation: Awaited<ReturnType<typeof observeChainPermission>> | undefined;
    let retryPositivelySafe = journalReadable;
    if (prior?.value.state === "superseded") {
      permissionObservation = await observeChainPermission(binding, {
        installedAtBlock: entry.installation.blockNumber,
        notBefore: {
          blockNumber: prior.value.supersession.blockNumber,
          blockHash: prior.value.supersession.blockHash,
        },
      });
      retryPositivelySafe = permissionObservation?.status === "present";
    }
    if (
      value === null &&
      prior !== undefined &&
      (prior.value.state === "submission_attempted" ||
        prior.value.state === "submitted" ||
        prior.value.state === "included")
    ) {
      // Observation-first dispatch: an already submitted uninstall is proven
      // or disproven by the current observer transport alone and never needs a
      // fresh bundler route. Observation submits zero new operations; only
      // finalized success of the retained operation completes the entry here.
      const observing = observationOnlyRunner(chainId);
      try {
        const observed = await runOnce(observing, "revocation", laneKey);
        if (
          observed.status === "observed" &&
          observed.record.value.state === "finalized" &&
          observed.record.value.inclusion.outcome === "success"
        ) {
          value = observed.record.value;
        } else if (observed.status === "observed" && observed.record.value.state === "superseded") {
          // Observation proved the submitted uninstall superseded; fence a
          // replacement exactly like a superseded journal record does.
          permissionObservation ??= await observeChainPermission(binding, {
            installedAtBlock: entry.installation.blockNumber,
            notBefore: {
              blockNumber: observed.record.value.supersession.blockNumber,
              blockHash: observed.record.value.supersession.blockHash,
            },
          });
          retryPositivelySafe = permissionObservation?.status === "present";
        }
      } finally {
        await observing.close().catch(() => undefined);
      }
    }
    if (value === null && retryPositivelySafe && input.ownerRevocations === null) {
      let result: OperationRunResult | null = null;
      try {
        const chain = chainCapability(chainId);
        const runtime = ownerRuntime(chainId);
        const deployment = runtime.deployment;
        requireKernelCapability(chainId, kernelKeyCapability("owner", input.ownerKey.kind));
        const calls =
          input.installApproval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
            ? kernelV33PermissionRevocationCalls({
                approval: input.installApproval,
                state: parseKernelV33PermissionState(
                  await chain.reads.read({ type: "kernel_v33_permission_state", ...binding }),
                ),
              })
            : encodeKernelV4PermissionUninstallCalls({
                account: entry.account,
                packages: input.installApproval.packages,
              });
        if (calls.length > 0) {
          const bundler = await probeBundlerCapability({
            capability: chain.bundler,
            request: { chainId, entryPoint: deployment.entryPoint.address },
            timeoutMs: SUBMISSION_TIMEOUT_MS,
          });
          const decision = decideExecution({
            operationKind: "revocation",
            sessionCoverage: "uncovered",
            bundler,
            feePayer: chain.feePayer,
          });
          const descriptor =
            decision.route === "none" ? null : await accountDescriptor(chainId, runtime);
          if (descriptor !== null && descriptor.account === entry.account) {
            // The retry fence was decided against an earlier journal read.
            // Re-read the lane now that the async bundler probe and account
            // composition completed: a submitted uninstall a concurrent observer
            // just proved superseded must be fenced by the same post-supersession
            // permission evidence as a superseded journal record. A stale boolean
            // never authorizes replacement publication.
            const lane = (await journal.get(laneKey).catch(() => undefined)) ?? prior;
            if (
              lane?.value.state === "finalized" &&
              lane.value.inclusion.outcome === "success" &&
              lane.value.identity.account === entry.account
            ) {
              value = lane.value;
            }
            if (value === null && lane?.value.state === "superseded") {
              permissionObservation ??= await observeChainPermission(binding, {
                installedAtBlock: entry.installation.blockNumber,
                notBefore: {
                  blockNumber: lane.value.supersession.blockNumber,
                  blockHash: lane.value.supersession.blockHash,
                },
              });
              retryPositivelySafe = permissionObservation?.status === "present";
            }
            if (value === null && retryPositivelySafe) {
              const sender = runner({
                chainId,
                kind: "revocation",
                runtime,
                descriptor,
                calls,
                signer: "owner",
                mode: "standard",
                materializer: null,
                decision,
                terminalBehavior: "replace",
                grantId: latest.value.identity.grantId,
                requestHash: null,
                authorizeOperation: (operation: OaathProviderOperationPointer) =>
                  authorizeRevocationOperation(binding, operation),
              });
              try {
                result = await runOnce(sender, "revocation", laneKey);
              } finally {
                // A cleanup failure never replaces the outcome of the run.
                await sender.close().catch(() => undefined);
              }
            }
          }
        }
      } catch {
        // The realm cannot mint or route the owner operation here; the
        // observation fallback below is its only completion path.
        result = null;
      }
      if (
        result !== null &&
        result.status === "observed" &&
        result.record.value.state === "finalized" &&
        result.record.value.inclusion.outcome === "success"
      ) {
        value = result.record.value;
      }
    }
    if (value !== null) {
      latest = await refresh();
      return commit(
        latest,
        transition(latest.value, {
          type: "record_chain_revoked",
          identity: latest.value.identity,
          binding,
          removal: {
            ...binding,
            kind: "permission_absent",
            blockNumber: value.finality.blockNumber,
            blockHash: value.finality.blockHash,
            observedAt: value.finality.observedAt,
          },
        }),
      );
    }
    // No owner operation completed here. If the owner's console or an ambiguous
    // prior attempt already removed the permission, the chain proves it.
    permissionObservation ??= await observeChainPermission(binding, {
      installedAtBlock: entry.installation.blockNumber,
    });
    if (permissionObservation?.status !== "absent") return latest;
    latest = await refresh();
    return commit(
      latest,
      transition(latest.value, {
        type: "record_chain_revoked",
        identity: latest.value.identity,
        binding,
        removal: permissionObservation.removal,
      }),
    );
  }

  /** Unused v3.3 approvals still need a journaled, owner-authorized nonce consumption. */
  async function revokeUnusedV33Approval(binding: Readonly<ChainBinding>): Promise<void> {
    const approval = input.installApproval;
    if (approval?.version !== OAATH_KERNEL_V33_APPROVAL_VERSION || input.ownerRevocations !== null)
      return;
    const snapshot = await refresh();
    const materialization = snapshot.value.materializations.find(
      (entry) => entry.chainId === binding.chainId,
    );
    if (materialization !== undefined && materialization.state !== "unmaterialized") return;
    const laneKey = {
      grantId: snapshot.value.identity.grantId,
      chainId: binding.chainId,
      kind: "revocation" as const,
    };
    const journal = operationStore();
    let prior: OperationStoreRecord | undefined;
    try {
      prior = await journal.get(laneKey);
    } finally {
      await journal.close();
    }
    if (
      prior?.value.state === "submission_attempted" ||
      prior?.value.state === "submitted" ||
      prior?.value.state === "included"
    ) {
      const observing = observationOnlyRunner(binding.chainId);
      try {
        await runOnce(observing, "revocation", laneKey);
      } finally {
        await observing.close().catch(() => undefined);
      }
      return;
    }
    if (prior?.value.state === "finalized" && prior.value.inclusion.outcome === "success") return;
    const chain = chainCapability(binding.chainId);
    const runtime = ownerRuntime(binding.chainId);
    const descriptor = await accountDescriptor(binding.chainId, runtime);
    if (descriptor.account !== binding.account || binding.permissionId !== approval.permissionId)
      return clientFail(
        "oaath_client_state_conflict",
        "revocation target contradicts its approval",
      );
    const state = parseKernelV33PermissionState(
      await chain.reads.read({ type: "kernel_v33_permission_state", ...binding }),
    );
    const calls = kernelV33PermissionRevocationCalls({ approval, state });
    if (calls.length === 0) return;
    const bundler = await classifiedBundler(
      binding.chainId,
      chain,
      runtime.deployment.entryPoint.address,
    );
    const decision = decideExecution({
      operationKind: "revocation",
      sessionCoverage: "uncovered",
      bundler,
      feePayer: chain.feePayer,
    });
    if (decision.route === "none") return;
    const sender = runner({
      chainId: binding.chainId,
      kind: "revocation",
      runtime,
      descriptor,
      calls,
      signer: "owner",
      mode: "standard",
      materializer: null,
      decision,
      terminalBehavior: "replace",
      grantId: snapshot.value.identity.grantId,
      requestHash: null,
      authorizeOperation: (operation) => authorizeRevocationOperation(binding, operation),
    });
    try {
      await runOnce(sender, "revocation", laneKey);
    } finally {
      await sender.close().catch(() => undefined);
    }
  }

  async function revokeGrant(): Promise<void> {
    let snapshot = await refresh();
    let grant = snapshot.value;
    if (grant.state === "revoked") return;
    if (grant.state !== "active" && grant.state !== "revoking") {
      clientFail(
        "oaath_client_grant_inactive",
        "the Grant cannot be revoked",
        `grant_${grant.state}`,
      );
    }
    if (grant.state === "active") {
      const approval = input.installApproval;
      if (approval === null)
        return clientFail(
          "oaath_client_state_conflict",
          "revocation requires its retained install approval",
        );
      const targets = new Map<number, Readonly<ChainBinding>>();
      for (const entry of grant.materializations) {
        if (entry.state === "unsupported") continue;
        targets.set(entry.chainId, {
          chainId: entry.chainId,
          account: entry.account,
          permissionId: entry.permissionId,
        });
      }
      for (const chainId of input.chains.keys()) {
        const validation = sessionRuntime(chainId).validation;
        if (validation.kind !== "permission")
          return clientFail(
            "oaath_client_state_conflict",
            "revocation requires a permission binding",
          );
        targets.set(chainId, {
          chainId,
          account: approval.account,
          permissionId: validation.permissionId,
        });
      }
      snapshot = await commit(
        snapshot,
        transition(grant, {
          type: "begin_revocation",
          identity: grant.identity,
          revocationStartedAt: input.now(),
          targets: [...targets.values()].sort((a, b) => a.chainId - b.chainId),
          installNonce: kernelGrantApprovalNonce(approval),
        }),
      );
      grant = snapshot.value;
    }
    // Stop service admission first. The owner signature remains valid on a
    // chain until that chain's install nonce is consumed.
    if (grant.capabilityInvalidation === null) {
      snapshot = await commit(snapshot, await invalidateCapability(grant));
      grant = snapshot.value;
    }
    // Each chain-local installed permission is removed on that chain by an
    // owner-signed revocation operation. A realm holding the owner's signing
    // capability completes it here; one that does not (URL mode never holds
    // owner authority) leaves the chain pending. The Grant stays durably
    // `revoking` until every chain's removal is conclusively observed.
    for (const original of [...grant.materializations]) {
      if (!input.chains.has(original.chainId)) continue;
      let entry = grant.materializations.find(
        (candidate) => candidate.chainId === original.chainId,
      );
      if (entry?.state === "installing") {
        snapshot = await reconcileInstallingMaterialization(
          snapshot,
          {
            chainId: entry.chainId,
            account: entry.account,
            permissionId: entry.permissionId,
          },
          entry.operationId,
          true,
        );
        grant = snapshot.value;
        entry = grant.materializations.find((candidate) => candidate.chainId === original.chainId);
      }
      if (entry !== undefined) snapshot = await revokeChainPermission(snapshot, entry);
      grant = snapshot.value;
    }
    if (
      grant.revocation === null ||
      input.installApproval === null ||
      grant.revocation.installNonce !== kernelGrantApprovalNonce(input.installApproval)
    )
      return clientFail(
        "oaath_client_state_conflict",
        "revocation scope contradicts its install approval",
      );
    const requestFailures: unknown[] = [];
    for (const binding of grant.revocation.targets) {
      if (grant.revocation?.evidence.some((entry) => entry.permission.chainId === binding.chainId))
        continue;
      const chain = input.chains.get(binding.chainId);
      // A removed configuration entry cannot remove an already recorded obligation.
      let evidence = chain
        ? await observeKernelPermissionRevocation({
            binding,
            approval: input.installApproval,
            observation: chain.observation,
            now: input.now,
          })
        : null;
      if (
        evidence === null &&
        chain &&
        input.installApproval.version === OAATH_KERNEL_V33_APPROVAL_VERSION
      ) {
        try {
          await revokeUnusedV33Approval(binding);
        } catch {
          /* Unavailable state never authorizes another submission or completion. */
        }
        evidence = await observeKernelPermissionRevocation({
          binding,
          approval: input.installApproval,
          observation: chain.observation,
          now: input.now,
        });
      }
      if (evidence === null) {
        if (input.ownerRevocations) {
          try {
            await input.ownerRevocations.request({
              grantId: grant.identity.grantId,
              chainId: binding.chainId,
            });
          } catch (error) {
            requestFailures.push(error);
          }
        }
        continue;
      }
      snapshot = await commit(
        snapshot,
        transition(grant, {
          type: "record_revocation_evidence",
          identity: grant.identity,
          evidence,
        }),
      );
      grant = snapshot.value;
    }
    if (requestFailures.length > 0)
      return mapClientFailure(requestFailures[0], "owner revocation request failed");
    if (
      grant.revocation === null ||
      grant.revocation.evidence.length !== grant.revocation.targets.length ||
      grant.materializations.some(
        (entry) =>
          entry.state !== "unsupported" &&
          entry.state !== "unmaterialized" &&
          entry.state !== "revoked",
      )
    ) {
      return;
    }
    await commit(
      snapshot,
      transition(grant, {
        type: "complete_revocation",
        identity: grant.identity,
        revokedAt: input.now(),
      }),
    );
  }

  async function revoke(): Promise<void> {
    assertOpen();
    revocationRequested = true;
    const active =
      revoking ??
      (async () => {
        await waitForExecutions();
        await revokeGrant();
      })();
    revoking = active;
    try {
      await active;
    } finally {
      if (revoking === active) revoking = null;
    }
  }

  async function account(chain: unknown): Promise<`0x${string}`> {
    assertOpen();
    if (typeof chain !== "number" || !Number.isSafeInteger(chain) || chain < 1) {
      return clientFail("oaath_client_input_invalid", "account chain is invalid");
    }
    return (await accountDescriptor(chain)).account;
  }

  async function authorizedAccount(chain: unknown): Promise<`0x${string}`> {
    assertOpen();
    if (revocationRequested) {
      return clientFail(
        "oaath_client_grant_inactive",
        "the Grant is being revoked",
        "grant_revocation_requested",
      );
    }
    await requireActive();
    return account(chain);
  }

  const handle: Readonly<OaathGrantHandle> = Object.freeze({
    get state(): GrantState {
      return record.value.state;
    },
    get expiresAt(): number {
      return record.value.expiresAt;
    },
    account,
    reviewCalls,
    sendCalls,
    getOperation,
    revoke,
    async close(): Promise<void> {
      if (closed) return;
      closeRequested = true;
      const active =
        closing ??
        (async () => {
          await waitForExecutions();
          await waitForActivities();
          if (revoking !== null) await revoking.catch(() => undefined);
          const failures: unknown[] = [];
          for (const operation of [...handles]) {
            await operation.close().catch((error: unknown) => failures.push(error));
          }
          for (const [chainId, created] of [...observers]) {
            await created
              .close()
              .then(() => {
                if (observers.get(chainId) === created) observers.delete(chainId);
              })
              .catch((error: unknown) => failures.push(error));
          }
          const failure = failures[0];
          if (failure !== undefined) {
            return mapClientFailure(failure, "Grant handle cleanup is incomplete");
          }
          closed = true;
        })();
      closing = active;
      try {
        await active;
      } finally {
        if (closing === active) closing = null;
      }
    },
  });
  GRANT_PROVIDER_PORTS.set(
    handle,
    Object.freeze({
      providerScopeId: input.binding.bindingId,
      grantId: record.value.identity.grantId,
      walletCallBundles: input.walletCallBundles,
      preparedCallContexts: input.preparedCallContexts,
      now: input.now,
      account,
      authorizedAccount,
      registeredPaymasterServiceUrl,
      staticPaymasterConfigurationHash,
      admitExecutionRoute,
      probeValidityTimeRangeSupport,
      admitValidityTimeRange,
      startCalls,
      prepareCalls,
      validatePreparedCalls,
      startPreparedCalls,
      recoverOperation,
      abandonPreparedOperation,
    }),
  );
  return handle;
}
