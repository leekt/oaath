/**
 * `@oaath/sdk/kernel` — the version-agnostic Kernel runtime, key, policy,
 * account and permission primitives, plus the prepared-operation vocabulary
 * they produce. Kernel and EntryPoint versions are optional settings; no
 * `@oaath/sdk` entry exports a version-named value or type.
 * For owner devices, custom deployments, and audits; the default application
 * path never needs them.
 *
 * @author taek <leekt216@gmail.com>
 */

// Cetane owns bounded history discovery and state confirmation. Keep one reader.
export {
  type KernelModuleSnapshot,
  type ObservedModule,
  type ReadModulesOptions,
  readKernelModules,
} from "cetane/accounts/kernel";

export type {
  DiagnoseKernelCapabilityInput,
  KernelCapability,
  KernelCapabilityEvidence,
  KernelCapabilityFact,
  KernelCapabilityReason,
  KernelCapabilityStatus,
} from "./kernel/capabilities.js";
export { diagnoseKernelCapability } from "./kernel/capabilities.js";
export { createKernelRuntime } from "./kernel/create-kernel-runtime.js";
export type {
  BindDerivedKernelAccountInput,
  BindEcdsaOwnerKernelAccountInput,
  BindExistingKernelAccountInput,
  BindKernelAccountInput,
  DeriveKernelAccountInput,
  KernelAccountDerivation,
  KernelAccountDescriptor,
  KernelDeploymentInput,
  KernelEntryPointVersion,
  KernelReadClient,
  KernelReadRequest,
  KernelReads,
  KernelVersion,
  PrepareKernelUserOperationInput,
} from "./kernel/deployment/account.js";
export {
  bindKernelAccount,
  createKernelReads,
  deriveKernelAccount,
  kernelAccountDeployment,
  kernelDeployment,
  prepareKernelUserOperation,
} from "./kernel/deployment/account.js";
export type { KernelDeployment } from "./kernel/deployment/profile.js";
/** ZeroDev's ECDSA validator: the ECDSA root of OAAth-derived accounts on every Kernel version. */
export { ECDSA_VALIDATOR } from "./kernel/deployment/v33.js";
export type { KernelGasPolicy } from "./kernel/gas-policy.js";
export type {
  EcdsaKeyAccount,
  EcdsaKeyInput,
  EcdsaSignRequest,
  EcdsaWalletClient,
  EcdsaWalletKeyInput,
} from "./kernel/key/ecdsa.js";
export {
  type EnrolledWebAuthnCredential,
  type EnrolWebAuthnCredentialInput,
  enrolWebAuthnCredential,
  OaathWebAuthnEnrolmentError,
  type WebAuthnEnrolmentErrorCode,
} from "./kernel/key/enrol-webauthn.js";
export type { KernelKeyInput, KernelPublicKeyInput } from "./kernel/key/kernel-key.js";
export { kernelKey } from "./kernel/key/kernel-key.js";
export type { P256KeyInput, P256SignRequest } from "./kernel/key/p256.js";
export type { WebAuthnAssertionRequest, WebAuthnKeyInput } from "./kernel/key/webauthn.js";
export type { WeightedEcdsaGuardian, WeightedEcdsaKeyInput } from "./kernel/key/weighted-ecdsa.js";
export {
  OAATH_KERNEL_RATE_LIMIT_POLICY,
  OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH,
  pinnedPolicyModule,
  pinnedSignerModule,
} from "./kernel/modules.js";
export type { OwnerOperatorInput } from "./kernel/operator/owner.js";
export { ownerOperator } from "./kernel/operator/owner.js";
export type {
  OwnerOperationRelyingParty,
  PreparedOwnerOperation,
  PrepareOwnerOperationInput,
  PrepareOwnerPermissionUninstallInput,
  VerifiedOwnerOperation,
} from "./kernel/operator/owner-operation.js";
export {
  prepareOwnerOperation,
  prepareOwnerPermissionUninstall,
  verifyOwnerOperation,
} from "./kernel/operator/owner-operation.js";
export type { SessionOperatorInput } from "./kernel/operator/session.js";
export { sessionOperator } from "./kernel/operator/session.js";
export type {
  ApproveKernelPermissionInput,
  BindKernelPermissionEnableInput,
  KernelGrantApproval as KernelPermissionApproval,
  KernelPermissionApprovalVerification,
  KernelPermissionEnable,
  KernelPermissionEnableTypedData,
  KernelPermissionNonceAlignmentInput,
  KernelPermissionNonceInput,
  MaterializeKernelPermissionInput,
  SignedKernelPermissionApprovalInput,
} from "./kernel/permission/approval.js";
export {
  approveKernelPermission,
  bindKernelPermissionEnable,
  kernelGrantCapabilityHash as kernelPermissionCapabilityHash,
  kernelPermissionEnableTypedData,
  kernelPermissionNonce,
  kernelPermissionNonceAlignmentCalls,
  materializeKernelPermission,
  parseVersionedKernelGrantApproval as parseKernelPermissionApproval,
  signedKernelPermissionApproval,
  verifyKernelPermissionApproval,
} from "./kernel/permission/approval.js";
export { compileKernelPermissionPolicy } from "./kernel/permission/compile.js";
export type { KernelPermissionMaterialization } from "./kernel/permission/materialize.js";
export { OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION } from "./kernel/permission/materialize.js";
export type {
  KernelPermissionRevocationVerification,
  KernelPermissionStatus,
  ReadKernelPermissionStatusInput,
  VerifyKernelPermissionRevocationInput,
} from "./kernel/permission/observe-revocation.js";
export {
  readKernelPermissionStatus,
  verifyKernelPermissionRevocation,
} from "./kernel/permission/observe-revocation.js";
export type {
  ExistingAccountApproval as KernelExistingAccountApproval,
  ExistingAccountApprovalChain as KernelExistingAccountApprovalChain,
  KernelPermissionDecision,
  PrepareDerivedAccountPermissionApprovalInput,
  PreparedKernelPermissionApproval,
  PrepareExistingAccountPermissionApprovalInput,
  PrepareKernelPermissionApprovalInput,
} from "./kernel/permission/prepare-approval.js";
export {
  prepareDerivedAccountPermissionApproval,
  prepareExistingAccountPermissionApproval,
  prepareKernelPermissionApproval,
} from "./kernel/permission/prepare-approval.js";
export type {
  KernelPermissionRevocationPreparation,
  KernelRecordedRevocation,
  PrepareKernelPermissionRevocationInput,
  RestoreKernelPermissionRevocationInput,
} from "./kernel/permission/revocation.js";
export {
  OAATH_KERNEL_PERMISSION_REVOCATION_VERSION,
  prepareKernelPermissionRevocation,
  restoreKernelPermissionRevocation,
} from "./kernel/permission/revocation.js";
export type {
  KernelV33ApprovalMismatchField as KernelApprovalMismatchField,
  KernelV33ApprovalMismatchReason as KernelApprovalMismatchReason,
  KernelV33ExpectedPermission as KernelExpectedPermission,
} from "./kernel/permission/v33.js";
export { OAATH_KERNEL_V33_APPROVAL_VERSION as OAATH_KERNEL_PERMISSION_ENABLE_APPROVAL_VERSION } from "./kernel/permission/v33.js";
export {
  type KernelPermissionNonceAlignmentVerification,
  NONCE_ALIGNMENT_PERMISSION_ID,
  type VerifyKernelPermissionNonceAlignmentCallsInput,
  verifyKernelPermissionNonceAlignmentCalls,
} from "./kernel/permission/v33-revocation.js";
export type {
  KernelRuntimeModule,
  KernelRuntimeModuleDeployment,
  KernelRuntimeModuleReadiness,
  KernelRuntimeModuleStatus,
  KernelRuntimeReadiness,
  KernelRuntimeReadinessInput,
  PrepareRuntimeModuleDeploymentInput,
} from "./kernel/runtime-modules.js";
export {
  kernelRuntimeReadiness,
  prepareRuntimeModuleDeployment,
} from "./kernel/runtime-modules.js";
export type {
  CompiledKernelPermissionPolicy,
  KernelBuiltInKeyKind,
  KernelCall,
  KernelCallPolicyPermission,
  KernelCallPolicyProfile,
  KernelCustomKeyKind,
  KernelExpiryPolicyProfile,
  KernelInstall,
  KernelKeyKind,
  KernelOperationLimitPolicyProfile,
  KernelOperatorAuthority,
  KernelPolicyProfile,
  KernelRateLimitPolicyProfile,
  KernelRuntimeBindAccountInput,
  KernelRuntimeErrorCode,
  KernelRuntimeExistingAccountInput,
  KernelRuntimePrepareInput,
  KernelRuntimeValidationMode,
  KernelUserOperationGas,
  KernelValidation,
  KernelValidityTimeRange,
  KeyOperationContext,
  KeyProfile,
  OperatorProfile,
  SelectedCreateKernelRuntimeInput as CreateKernelRuntimeInput,
  SelectedKernelRuntime as KernelRuntime,
} from "./kernel/types.js";
export { OaathKernelRuntimeError } from "./kernel/types.js";
export type { ReviewedKernelImplementation } from "./kernel-v4.js";
export type {
  PreparedEntryPoint,
  PreparedFactory,
  PreparedPaymaster,
  PreparedUserOperation,
  PreparedUserOperationErrorCode,
  UnsignedUserOperationV07,
} from "./prepared-user-operation.js";
export {
  asCetaneUserOperation,
  deriveOperationId,
  OAATH_PREPARED_USER_OPERATION_VERSION,
  OaathPreparedUserOperationError,
  parsePreparedUserOperation,
  prepareUserOperation,
} from "./prepared-user-operation.js";
