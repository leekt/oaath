/**
 * `@oaath/sdk/advanced` — custom-deployment ports, the version-named Kernel
 * encoders and deployment constants custom deployments and fixtures need, and
 * the fully overridden composition: binding capture, chain capabilities, routing, the operation
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
  OaathChainSponsorship,
  OaathOwnerRevocationCapability,
  OaathQuoteCapability,
  OaathQuoteRequest,
  OaathSubmissionCapability,
  OaathSubmissionRequest,
  OaathSubmissionRoute,
  OaathUsageRequest,
} from "./client/grant-handle.js";
export type {
  OaathConfiguration,
  OaathSigningConfiguration,
  OaathStoreConfiguration,
} from "./create-oaath.js";
export type {
  KernelNonceKeyInput,
  KernelOperationSigningHashInput,
} from "./kernel/deployment/account.js";
export {
  encodeKernelNonceKey,
  kernelOperationSigningHash,
} from "./kernel/deployment/account.js";
export {
  encodeKernelV33NonceKey,
  kernelV33OperationSigningHash,
} from "./kernel/deployment/v33-operation.js";
export {
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY as OAATH_KERNEL_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH as OAATH_KERNEL_VALIDITY_POLICY_RUNTIME_CODE_HASH,
} from "./kernel/modules.js";
export { deriveSessionPolicyProfiles } from "./kernel/permission/profiles.js";
export {
  kernelV33PermissionEnableTypedData,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
} from "./kernel/permission/v33.js";
export type { KernelV33PermissionState } from "./kernel/permission/v33-revocation.js";
export {
  kernelV33EffectivePermissionNonce,
  kernelV33PermissionRevocationCalls,
  kernelV33PermissionStatus,
  parseKernelV33PermissionState,
  readKernelV33PermissionState,
} from "./kernel/permission/v33-revocation.js";
export type {
  KernelV4NonceKeyInput,
  KernelV4NonceReadInput,
  KernelV4NonceReadInput as KernelNonceReadInput,
  KernelV4ReplayableInstallDigestInput,
  KernelV4ReplayableInstallDigestInput as KernelReplayableInstallDigestInput,
} from "./kernel-v4.js";
export {
  encodeKernelV4FactoryImplementationRead,
  encodeKernelV4FactoryImplementationRead as encodeKernelFactoryImplementationRead,
  encodeKernelV4InstallNonceInvalidationCall,
  encodeKernelV4InstallNonceInvalidationCall as encodeKernelInstallNonceInvalidationCall,
  encodeKernelV4InstallNonceRead,
  encodeKernelV4InstallNonceRead as encodeKernelInstallNonceRead,
  encodeKernelV4NonceKey,
  encodeKernelV4NonceRead,
  encodeKernelV4NonceRead as encodeKernelNonceRead,
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  kernelV4ReplayableInstallDigest,
  kernelV4ReplayableInstallDigest as kernelReplayableInstallDigest,
} from "./kernel-v4.js";
export type {
  ObserveOperationResult,
  ObserveUserOperationInput,
  ObserveUserOperationResult,
  OperationObserver,
  OperationObserverBlockEvidence,
  OperationObserverCapabilities,
  OperationObserverErrorCode,
  OperationObserverLogEvidence,
  OperationObserverReadRequest,
  OperationObserverTransactionEvidence,
  OperationObserverTransactionReceiptEvidence,
  OperationObserverUserOperationReceiptEvidence,
  UserOperationObserver,
  VerifiedOperationReceiptEvidence,
} from "./operation-observer.js";
export {
  createOperationObserver,
  createUserOperationObserver,
  OaathOperationObserverError,
} from "./operation-observer.js";
export type {
  OperationObserveResult,
  OperationPreparationCapability,
  OperationRunInput,
  OperationRunner,
  OperationRunnerConfiguration,
  OperationRunnerErrorCode,
  OperationRunResult,
  OperationStartResult,
  OperationSubmissionCapability,
  OperationSubmissionSession,
  OperationTerminalBehavior,
} from "./operation-runner.js";
export {
  createOperationRunner,
  OaathOperationRunnerError,
} from "./operation-runner.js";
export type {
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
export {
  ERC7902_STATIC_PAYMASTER_CONFIGURATION_HASH_DOMAIN,
  ERC7902_STATIC_PAYMASTER_LIMITS,
  hashErc7902StaticPaymasterConfiguration,
} from "./provider/erc7902.js";
export type {
  OaathBundlerCapability,
  OaathRouteFact,
  OaathRoutingCapabilities,
  OaathSessionCoverage,
} from "./routing/capabilities.js";
export { captureRoutingCapabilities } from "./routing/capabilities.js";
export type { DecideExecutionInput } from "./routing/decide.js";
export { decideExecution } from "./routing/decide.js";
export type {
  OaathBundlerAcceptanceEvidence,
  OaathBundlerProbeCapability,
  OaathBundlerProbeEvidence,
  OaathBundlerProbeInput,
  OaathBundlerProbeRequest,
} from "./routing/erc4337/bundler.js";
export {
  classifyBundlerAcceptance,
  classifyBundlerProbe,
  OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES,
  probeBundlerCapability,
} from "./routing/erc4337/bundler.js";
export type { OaathOperationPrefund } from "./routing/erc4337/gas.js";
export { deriveOperationPrefund } from "./routing/erc4337/gas.js";
export type {
  OaathHandleOpsCall,
  OaathHandleOpsEncodingInput,
  OaathHandleOpsRequirement,
  OaathHandleOpsRequirementInput,
} from "./routing/erc4337/handle-ops.js";
export {
  deriveHandleOpsRequirement,
  encodeHandleOps,
  OAATH_HANDLE_OPS_OVERHEAD_GAS,
} from "./routing/erc4337/handle-ops.js";
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
  OaathRouteReasonCode,
  OaathSubmissionRouteKind,
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
  OperationStoreScope,
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
