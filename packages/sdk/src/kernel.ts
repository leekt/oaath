/**
 * `@oaath/sdk/kernel` — the reviewed Kernel v4 runtime, key, policy, and
 * permission primitives, plus the prepared-operation vocabulary they produce.
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
export {
  encodeKernelV33NonceKey,
  kernelV33OperationSigningHash,
} from "./kernel/deployment/v33-operation.js";
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
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
  pinnedPolicyModule,
  pinnedSignerModule,
} from "./kernel/modules.js";
export type { OwnerOperatorInput } from "./kernel/operator/owner.js";
export { ownerOperator } from "./kernel/operator/owner.js";
export type { SessionOperatorInput } from "./kernel/operator/session.js";
export { sessionOperator } from "./kernel/operator/session.js";
export type { KernelPermissionApprovalVerification } from "./kernel/permission/approval.js";
export { verifyKernelPermissionApproval } from "./kernel/permission/approval.js";
export { compileKernelPermissionPolicy } from "./kernel/permission/compile.js";
export { kernelPermissionInstallNonce } from "./kernel/permission/install-nonce.js";
export type {
  ApproveKernelPermissionAllChainInput,
  KernelAllChainApproval,
  KernelPermissionMaterialization,
  MaterializeKernelPermissionInput,
} from "./kernel/permission/materialize.js";
export {
  approveKernelPermissionAllChain,
  kernelAllChainCapabilityHash,
  materializeKernelPermission,
  OAATH_KERNEL_ALL_CHAIN_APPROVAL_VERSION,
  parseKernelAllChainApproval,
} from "./kernel/permission/materialize.js";
export type {
  KernelPermissionRevocationVerification,
  VerifyKernelPermissionRevocationInput,
} from "./kernel/permission/observe-revocation.js";
export { verifyKernelPermissionRevocation } from "./kernel/permission/observe-revocation.js";
export type {
  KernelPhonePermissionArtifact,
  PreparedKernelPhonePermissionApproval,
  PrepareKernelPhonePermissionApprovalInput,
} from "./kernel/permission/phone-approval.js";
export { prepareKernelPhonePermissionApproval } from "./kernel/permission/phone-approval.js";
export type {
  PreparedKernelPhoneRevocation,
  PrepareKernelPhoneRevocationInput,
} from "./kernel/permission/phone-revocation.js";
export {
  prepareKernelPhoneRevocation,
  restoreKernelPhoneRevocation,
} from "./kernel/permission/phone-revocation.js";
export type {
  KernelPermissionRevocationPreparation,
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
  ApproveKernelV33PermissionInput,
  KernelV33ApprovalMismatchField,
  KernelV33ApprovalMismatchReason,
  KernelV33ExpectedPermission,
  KernelV33PermissionApproval,
  KernelV33PermissionScope,
  MaterializeKernelV33PermissionInput,
} from "./kernel/permission/v33.js";
export {
  approveKernelV33Permission,
  kernelV33CapabilityHash,
  kernelV33PermissionEnableTypedData,
  kernelV33PermissionInstallNonce,
  materializeKernelV33Permission,
  OAATH_KERNEL_V33_APPROVAL_VERSION,
  parseKernelV33PermissionApproval,
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
  CompiledKernelPermissionPolicy,
  CreateKernelRuntimeInput,
  KernelBuiltInKeyKind,
  KernelCallPolicyPermission,
  KernelCallPolicyProfile,
  KernelCustomKeyKind,
  KernelExpiryPolicyProfile,
  KernelKeyKind,
  KernelOperationLimitPolicyProfile,
  KernelOperatorAuthority,
  KernelPolicyProfile,
  KernelRateLimitPolicyProfile,
  KernelRuntime,
  KernelRuntimeBindAccountInput,
  KernelRuntimeErrorCode,
  KernelRuntimeExistingAccountInput,
  KernelRuntimePrepareInput,
  KernelRuntimeValidationMode,
  KeyProfile,
  OperatorProfile,
} from "./kernel/types.js";
export { OaathKernelRuntimeError } from "./kernel/types.js";
export type {
  KernelV4AccountInput,
  KernelV4Call,
  KernelV4EnableSignatureInput,
  KernelV4ErrorCode,
  KernelV4ExecutionInput,
  KernelV4Install,
  KernelV4ModuleDataInput,
  KernelV4ModuleType,
  KernelV4NonceInput,
  KernelV4NonceKeyInput,
  KernelV4NonceReadInput,
  KernelV4ReplayableInstallDigestInput,
  KernelV4SignerDataInput,
  KernelV4UserOperationGas,
  KernelV4UserOperationNonceInput,
  KernelV4Validation,
  KernelV4ValidationMode,
  KernelV4ValidityTimeRange,
} from "./kernel-v4.js";
export {
  encodeKernelV4EnableSignature,
  encodeKernelV4Execution,
  encodeKernelV4FactoryAddressRead,
  encodeKernelV4FactoryDeploy,
  encodeKernelV4FactoryImplementationRead,
  encodeKernelV4Initialize,
  encodeKernelV4InstallModules,
  encodeKernelV4InstallNonceInvalidationCall,
  encodeKernelV4InstallNonceRead,
  encodeKernelV4Nonce,
  encodeKernelV4NonceKey,
  encodeKernelV4NonceRead,
  encodeKernelV4PermissionSignature,
  encodeKernelV4PermissionUninstallCalls,
  encodeKernelV4PolicyData,
  encodeKernelV4SignerData,
  encodeKernelV4ValidatorData,
  KERNEL_V4_CREATE2_DEPLOYER,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_EXECUTE_SELECTOR,
  KERNEL_V4_EXECUTE_USER_OP_SELECTOR,
  KERNEL_V4_FACTORY_V07,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_IMPLEMENTATION_SLOT,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  kernelV4ReplayableInstallDigest,
  kernelV4ReplayableInstallTypedData,
  OaathKernelV4Error,
} from "./kernel-v4.js";
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
