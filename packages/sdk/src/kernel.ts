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
  BindExistingKernelAccountInput,
  BindKernelAccountInput,
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
  kernelAccountDeployment,
  kernelDeployment,
  prepareKernelUserOperation,
} from "./kernel/deployment/account.js";
export type { KernelDeployment } from "./kernel/deployment/profile.js";
export type { KernelGasPolicy } from "./kernel/gas-policy.js";
export type {
  EcdsaKeyAccount,
  EcdsaKeyInput,
  EcdsaSignRequest,
  EcdsaWalletClient,
  EcdsaWalletKeyInput,
} from "./kernel/key/ecdsa.js";
export type { KernelKeyInput, KernelPublicKeyInput } from "./kernel/key/kernel-key.js";
export { kernelKey } from "./kernel/key/kernel-key.js";
export type { P256KeyInput, P256SignRequest } from "./kernel/key/p256.js";
export type { WebAuthnAssertionRequest, WebAuthnKeyInput } from "./kernel/key/webauthn.js";
export {
  OAATH_KERNEL_RATE_LIMIT_POLICY,
  OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH,
  pinnedPolicyModule,
  pinnedSignerModule,
} from "./kernel/modules.js";
export type { OwnerOperatorInput } from "./kernel/operator/owner.js";
export { ownerOperator } from "./kernel/operator/owner.js";
export type { SessionOperatorInput } from "./kernel/operator/session.js";
export { sessionOperator } from "./kernel/operator/session.js";
export type {
  ApproveKernelPermissionInput,
  KernelGrantApproval as KernelPermissionApproval,
  KernelPermissionApprovalVerification,
  KernelPermissionEnableTypedData,
  KernelPermissionNonceInput,
  MaterializeKernelPermissionInput,
  SignedKernelPermissionApprovalInput,
} from "./kernel/permission/approval.js";
export {
  approveKernelPermission,
  kernelGrantCapabilityHash as kernelPermissionCapabilityHash,
  kernelPermissionEnableTypedData,
  kernelPermissionNonce,
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
  VerifyKernelPermissionRevocationInput,
} from "./kernel/permission/observe-revocation.js";
export { verifyKernelPermissionRevocation } from "./kernel/permission/observe-revocation.js";
export type {
  KernelPermissionDecision,
  PreparedKernelPermissionApproval,
  PrepareKernelPermissionApprovalInput,
} from "./kernel/permission/prepare-approval.js";
export { prepareKernelPermissionApproval } from "./kernel/permission/prepare-approval.js";
export type {
  KernelPermissionRevocationPreparation,
  KernelRecordedRevocation,
  KernelSigningRequestRevocation,
  PreparedKernelPermissionRevocation,
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
  KeyProfile,
  OperatorProfile,
  SelectedCreateKernelRuntimeInput as CreateKernelRuntimeInput,
  SelectedKernelRuntime as KernelRuntime,
} from "./kernel/types.js";
export { OaathKernelRuntimeError } from "./kernel/types.js";
export type {
  PreparedEntryPoint,
  PreparedFactory,
  PreparedPaymaster,
  PreparedUserOperation,
  PreparedUserOperationErrorCode,
  UnsignedUserOperationV07,
} from "./prepared-user-operation.js";
export {
  asViemUserOperation,
  deriveOperationId,
  OAATH_PREPARED_USER_OPERATION_VERSION,
  OaathPreparedUserOperationError,
  parsePreparedUserOperation,
  prepareUserOperation,
} from "./prepared-user-operation.js";
