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
  EcdsaKeyAccount,
  EcdsaKeyInput,
  EcdsaSignRequest,
} from "./kernel/key/ecdsa.js";
export { ecdsaKey } from "./kernel/key/ecdsa.js";
export type {
  P256KeyInput,
  P256SignRequest,
} from "./kernel/key/p256.js";
export { p256Key } from "./kernel/key/p256.js";
export type {
  WebAuthnAssertionRequest,
  WebAuthnKeyInput,
} from "./kernel/key/webauthn.js";
export { webauthnKey } from "./kernel/key/webauthn.js";
export {
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
  pinnedPolicyModule,
  pinnedSignerModule,
} from "./kernel/modules.js";
export type { OwnerOperatorInput } from "./kernel/operator/owner.js";
export { ownerOperator } from "./kernel/operator/owner.js";
export type { SessionOperatorInput } from "./kernel/operator/session.js";
export { sessionOperator } from "./kernel/operator/session.js";
export { compileKernelPermissionPolicy } from "./kernel/permission/compile.js";
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
  KernelRuntime,
  KernelRuntimeBindAccountInput,
  KernelRuntimeErrorCode,
  KernelRuntimePrepareInput,
  KernelRuntimeValidationMode,
  KeyProfile,
  OperatorProfile,
} from "./kernel/types.js";
export { OaathKernelRuntimeError } from "./kernel/types.js";
export type {
  KernelV4AccountDescriptor,
  KernelV4AccountInput,
  KernelV4AccountReadCapability,
  KernelV4AccountReadRequest,
  KernelV4BindAccountInput,
  KernelV4Call,
  KernelV4Deployment,
  KernelV4EnableSignatureInput,
  KernelV4ErrorCode,
  KernelV4ExecutionInput,
  KernelV4Install,
  KernelV4ModuleDataInput,
  KernelV4ModuleType,
  KernelV4NonceInput,
  KernelV4NonceKeyInput,
  KernelV4NonceReadInput,
  KernelV4ReadClient,
  KernelV4ReplayableInstallDigestInput,
  KernelV4SignerDataInput,
  KernelV4UserOperationGas,
  KernelV4UserOperationInput,
  KernelV4UserOperationNonceInput,
  KernelV4Validation,
  KernelV4ValidationMode,
  KernelV4ValidityTimeRange,
} from "./kernel-v4.js";
export {
  bindKernelV4Account,
  createKernelV4Reads,
  encodeKernelV4EnableSignature,
  encodeKernelV4Execution,
  encodeKernelV4FactoryAddressRead,
  encodeKernelV4FactoryDeploy,
  encodeKernelV4FactoryImplementationRead,
  encodeKernelV4Initialize,
  encodeKernelV4InstallModules,
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
  kernelV4Deployment,
  kernelV4ReplayableInstallDigest,
  kernelV4ReplayableInstallTypedData,
  OaathKernelV4Error,
  prepareKernelV4UserOperation,
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
