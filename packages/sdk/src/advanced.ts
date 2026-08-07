/**
 * `@oaath/sdk/advanced` — custom-deployment ports and the fully overridden
 * composition: binding capture, chain capabilities, routing, the operation
 * runner/observer pair, stores, and cleanup. Injecting these bypasses the
 * service-owned execution path; they exist for deterministic tests and
 * deployments that deliberately own it.
 *
 * @author taek <leekt216@gmail.com>
 */
export type {
  OaathCleanupResult,
  RunOaathCleanupInput,
} from "./cleanup/coordinator.js";
export {
  OaathCleanupError,
  runOaathCleanup,
} from "./cleanup/coordinator.js";
export type { OaathCleanupEffect } from "./cleanup/effects.js";
export {
  closeEffect,
  forgetLocalEffect,
  revokeEffect,
  signOutEffect,
} from "./cleanup/effects.js";
export type {
  OaathBinding,
  OaathBindingInput,
} from "./client/binding.js";
export {
  captureOaathBinding,
  OAATH_BINDING_HASH_DOMAIN,
  OAATH_BINDING_VERSION,
} from "./client/binding.js";
export type {
  OaathAuthorizationCapability,
  OaathIssuerCapability,
} from "./client/connection.js";
export type {
  OaathCapabilityInvalidationCapability,
  OaathChainCapability,
  OaathQuoteCapability,
  OaathQuoteRequest,
  OaathRegisteredPaymasterService,
  OaathSubmissionCapability,
  OaathSubmissionRequest,
} from "./client/grant-handle.js";
export { deriveSessionPolicyProfiles } from "./client/grant-handle.js";
export type {
  OaathConfiguration,
  OaathSigningConfiguration,
  OaathStoreConfiguration,
} from "./create-oaath.js";
export type {
  ObserveOperationResult,
  OperationObserver,
  OperationObserverBlockEvidence,
  OperationObserverCapabilities,
  OperationObserverErrorCode,
  OperationObserverLogEvidence,
  OperationObserverReadRequest,
  OperationObserverTransactionEvidence,
  OperationObserverTransactionReceiptEvidence,
  OperationObserverUserOperationReceiptEvidence,
} from "./operation-observer.js";
export {
  createOperationObserver,
  OaathOperationObserverError,
} from "./operation-observer.js";
export type {
  OperationPreparationCapability,
  OperationRunInput,
  OperationRunner,
  OperationRunnerConfiguration,
  OperationRunnerErrorCode,
  OperationRunResult,
  OperationSubmissionCapability,
  OperationSubmissionSession,
  OperationTerminalBehavior,
} from "./operation-runner.js";
export {
  createOperationRunner,
  OaathOperationRunnerError,
} from "./operation-runner.js";
export type {
  CreateErc7677SponsorshipCapabilityInput,
  Erc7677EstimationUserOperationV07,
  Erc7677GasEstimationRequest,
  Erc7677GasEstimator,
  Erc7677JsonObject,
  Erc7677JsonValue,
  Erc7677PaymasterMethod,
  Erc7677PaymasterServiceRequest,
  Erc7677RegisteredPaymasterService,
  Erc7677UnsignedUserOperationV07,
} from "./provider/erc7677.js";
export { createErc7677SponsorshipCapability } from "./provider/erc7677.js";
export type { Erc7902StaticPaymasterConfiguration } from "./provider/erc7902.js";
export {
  captureErc7902StaticPaymasterConfiguration,
  ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN,
  ERC7902_STATIC_PAYMASTER_LIMITS,
  hashErc7902StaticPaymasterConfiguration,
} from "./provider/erc7902.js";
export type {
  OaathBundlerAcceptanceEvidence,
  OaathBundlerProbeCapability,
  OaathBundlerProbeEvidence,
  OaathBundlerProbeInput,
  OaathBundlerProbeRequest,
} from "./routing/bundler.js";
export {
  classifyBundlerAcceptance,
  classifyBundlerProbe,
  OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES,
  probeBundlerCapability,
} from "./routing/bundler.js";
export type {
  OaathBundlerCapability,
  OaathRoutingCapabilities,
  OaathSessionCoverage,
} from "./routing/capabilities.js";
export { captureRoutingCapabilities } from "./routing/capabilities.js";
export type { DecideExecutionInput } from "./routing/decide.js";
export { decideExecution } from "./routing/decide.js";
export type { OaathOperationPrefund } from "./routing/gas.js";
export { deriveOperationPrefund } from "./routing/gas.js";
export type {
  OaathHandleOpsCall,
  OaathHandleOpsEncodingInput,
  OaathHandleOpsRequirement,
  OaathHandleOpsRequirementInput,
} from "./routing/handle-ops.js";
export {
  deriveHandleOpsRequirement,
  encodeHandleOps,
  OAATH_HANDLE_OPS_OVERHEAD_GAS,
} from "./routing/handle-ops.js";
export type {
  OaathKernelSponsorshipCapability,
  OaathKernelSponsorshipRequest,
  OaathKernelSponsorshipResult,
  OaathKernelSponsorshipRuntime,
  PrepareSponsoredKernelOperationInput,
} from "./routing/sponsorship.js";
export { prepareSponsoredKernelOperation } from "./routing/sponsorship.js";
export type {
  OaathExecutionDecision,
  OaathExecutionReason,
  OaathExecutionRoute,
  OaathExecutionRouteReason,
  OaathExecutionSigner,
  OaathExecutionSignerDecision,
  OaathExecutionSignerReason,
  OaathFeePayerDescriptor,
  RoutingErrorCode,
} from "./routing/types.js";
export { OaathRoutingError } from "./routing/types.js";
export type {
  GrantStoreAdapter,
  GrantStoreCompareAndSwapResult,
  GrantStoreRecord,
  OperationStoreAdapter,
  OperationStoreArchive,
  OperationStoreCompareAndSwapResult,
  OperationStoreKey,
  OperationStoreRecord,
  StoreErrorCode,
  StoreRecord,
} from "./store.js";
export {
  GrantStore,
  OAATH_GRANT_STORE_RECORD_VERSION,
  OAATH_OPERATION_STORE_RECORD_VERSION,
  OaathStoreError,
  OperationStore,
} from "./store.js";
