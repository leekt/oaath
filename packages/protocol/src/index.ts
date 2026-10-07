export type { ClientBinding } from "./actors/client.js";
export {
  captureClientBinding,
  OAATH_CLIENT_BINDING_VERSION,
  parseClientBinding,
} from "./actors/client.js";
export type { IssuerIdentity } from "./actors/issuer.js";
export {
  captureIssuerIdentity,
  OAATH_ISSUER_VERSION,
  parseIssuerIdentity,
} from "./actors/issuer.js";
export type { SubjectBinding, SubjectBindingInput } from "./actors/subject.js";
export {
  captureSubjectBinding,
  createSubjectBinding,
  deriveSubjectId,
  OAATH_SUBJECT_HASH_DOMAIN,
  OAATH_SUBJECT_VERSION,
  parseSubjectBinding,
} from "./actors/subject.js";
export {
  type BundlerRejection,
  captureBundlerRejection,
  OAATH_CONCLUSIVE_BUNDLER_REJECTION_CODES,
  readRpcBundlerRejection,
} from "./bundler-rejection.js";
export { entryPointAbi } from "./entry-point-abi.js";
export type { ProtocolContractErrorCode } from "./errors.js";
export { OaathProtocolError } from "./errors.js";
export type {
  ActiveGrant,
  ApplicationBinding,
  ApprovedGrant,
  ChainBinding,
  ChainMaterialization,
  ChainPermissionEvidence,
  ChainRevocationEvidence,
  ExpiredGrant,
  Grant,
  GrantApproval,
  GrantCapabilityInvalidation,
  GrantErrorCode,
  GrantIdentity,
  GrantRevocation,
  GrantState,
  GrantTerminal,
  GrantTransition,
  InstalledMaterialization,
  InstallingMaterialization,
  MaterializationUnreadableReason,
  MaterializationUnsupportedReason,
  RejectedGrant,
  RequestedGrant,
  RevokedGrant,
  RevokedMaterialization,
  RevokingGrant,
  RevokingMaterialization,
  UnmaterializedMaterialization,
  UnreadableMaterialization,
  UnsupportedMaterialization,
} from "./grant.js";
export {
  advanceGrant,
  createGrant,
  OAATH_GRANT_RECORD_VERSION,
  OaathGrantError,
  parseGrant,
  sameGrantIdentity,
} from "./grant.js";
export type {
  CompleteGrantPolicyUsageEvidence,
  GrantPolicy,
  GrantPolicyArgumentEquality,
  GrantPolicyCall,
  GrantPolicyCoverageCall,
  GrantPolicyCoverageDeniedReason,
  GrantPolicyCoverageInconclusiveReason,
  GrantPolicyCoverageInput,
  GrantPolicyCoverageResult,
  GrantPolicyErrorCode,
  GrantPolicyOperationLimit,
  GrantPolicyUsageCheckpoint,
  GrantPolicyUsageEvidence,
  UnavailableGrantPolicyUsageEvidence,
} from "./grant-policy.js";
export {
  encodeGrantPolicy,
  evaluateGrantPolicyCoverage,
  hashGrantPolicy,
  hashGrantPolicyCalls,
  isGrantPolicyAttenuation,
  OAATH_GRANT_POLICY_CALLS_HASH_DOMAIN,
  OAATH_GRANT_POLICY_HASH_DOMAIN,
  OAATH_GRANT_POLICY_USAGE_VERSION,
  OAATH_GRANT_POLICY_VERSION,
  OaathGrantPolicyError,
  parseGrantPolicy,
} from "./grant-policy.js";
export type {
  GrantVerificationDeniedCode,
  GrantVerificationResult,
  GrantVerificationUnknownCode,
  OaathGrantRef,
  OaathGrantRefState,
  VerifyGrantRevisionInput,
} from "./grant-reference.js";
export {
  OAATH_GRANT_REFERENCE_APPROVED_REVISION,
  OAATH_GRANT_REFERENCE_VERSION,
  parseGrantVerificationResult,
  parseOaathGrantRef,
  parseVerifyGrantRevisionInput,
} from "./grant-reference.js";
export type {
  EcdsaOperatorCredentialProfile,
  EcdsaOwnerCredentialProfile,
  IdentityProfileErrorCode,
  KernelAccountActionInput,
  KernelAccountProfile,
  KernelDerivedAccountProfile,
  KernelExistingAccountProfile,
  KernelExistingAccountVersion,
  OperatorCredentialKind,
  OperatorCredentialProfile,
  OwnerCredentialKind,
  OwnerCredentialProfile,
  P256OwnerCredentialProfile,
  WebAuthnOperatorCredentialProfile,
  WebAuthnOwnerCredentialProfile,
} from "./identity-profile.js";
export {
  createKernelAccountActionInput,
  isKernelExistingAccountProfile,
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_KERNEL_EXISTING_ACCOUNT_PROFILE_VERSION,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OaathIdentityProfileError,
  parseKernelAccountProfile,
  parseOperatorCredentialProfile,
  parseOwnerCredentialProfile,
  sameKernelAccountProfile,
  sameOperatorCredentialProfile,
  sameOwnerCredentialProfile,
} from "./identity-profile.js";
export type {
  AccountId,
  ClientId,
  DeviceId,
  SubjectId,
} from "./ids.js";
export {
  parseAccountId,
  parseClientId,
  parseDeviceId,
  parseSubjectId,
} from "./ids.js";
export type {
  CaptureContext,
  CaptureFailure,
  ExactRecord,
} from "./internal/exact-record.js";
export {
  captureDenseArray,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "./internal/exact-record.js";
export type {
  KernelInstall,
  KernelModuleType,
  KernelReplayableInstallOwnerSigningRequest,
  KernelReplayableInstallPackage,
  KernelReplayableInstallTypedData,
  KernelReplayableInstallTypedDataInput,
} from "./kernel-v4-replayable-install.js";
export {
  createKernelReplayableInstallTypedData,
  KERNEL_INSTALL_COMPONENTS,
  parseKernelInstallPackages,
  parseKernelReplayableInstallOwnerSigningRequest,
} from "./kernel-v4-replayable-install.js";
export type {
  KernelRevocationEffect,
  KernelRevocationOperation,
  KernelRevocationSigningRequest,
} from "./kernel-v4-revocation.js";
export {
  encodeKernelInstallNonceInvalidationCall,
  encodeKernelPermissionUninstallCalls,
  hashKernelRevocationSigningRequest,
  OAATH_KERNEL_REVOCATION_SIGNING_REQUEST_VERSION,
  parseKernelRevocationSigningRequest,
} from "./kernel-v4-revocation.js";
export type {
  AbandonedOperation,
  DroppedOperation,
  FinalizedOperation,
  IncludedOperation,
  Operation,
  OperationAbandonment,
  OperationDropEvidence,
  OperationErrorCode,
  OperationFinality,
  OperationIdentity,
  OperationInclusion,
  OperationKind,
  OperationLane,
  OperationOutcome,
  OperationSubmissionEvidence,
  OperationSubmissionRoute,
  OperationSupersession,
  OperationTransition,
  OperationWeakObservation,
  PreparedOperation,
  SubmissionAttemptedOperation,
  SubmittedOperation,
  SupersededOperation,
  UserOperationReference,
} from "./operation.js";
export {
  advanceOperation,
  applyVerifiedOperationObservation,
  createOperation,
  OAATH_OPERATION_RECORD_VERSION,
  OaathOperationError,
  operationOccupiesLane,
  parseOperation,
  parseOperationIdentity,
  parseOperationLane,
  parseOperationSubmissionEvidence,
  parseUserOperationReference,
} from "./operation.js";
export type { OwnerSigningArtifact } from "./owner-signing-artifact.js";
export {
  OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
  parseOwnerSigningArtifact,
  serializeOwnerSigningArtifact,
} from "./owner-signing-artifact.js";
export type {
  ApplyPermissionDecisionInput,
  ApplyPermissionDecisionResult,
  ApprovePermissionDecision,
  PermissionDecision,
  PermissionDecisionObservation,
  PermissionProtocolErrorCode,
  PermissionRequest,
  PermissionSessionSigner,
  RejectPermissionDecision,
} from "./permission-protocol.js";
export {
  applyPermissionDecision,
  createGrantFromPermissionRequest,
  encodePermissionDecision,
  encodePermissionRequest,
  hashPermissionDecision,
  hashPermissionRequest,
  OAATH_PERMISSION_DECISION_HASH_DOMAIN,
  OAATH_PERMISSION_DECISION_VERSION,
  OAATH_PERMISSION_REQUEST_HASH_DOMAIN,
  OAATH_PERMISSION_REQUEST_VERSION,
  OaathPermissionProtocolError,
  parsePermissionDecision,
  parsePermissionRequest,
} from "./permission-protocol.js";
export { deriveCodeChallenge } from "./pkce.js";
export type {
  ServiceAccount,
  ServiceBootstrap,
  ServiceBootstrapApplication,
  ServiceBootstrapChain,
  ServiceBootstrapPaymasterService,
  ServiceBootstrapSessionSigner,
  ServiceBootstrapSessionSignerMode,
  WorkspaceAccountContext,
} from "./service-bootstrap.js";
export {
  captureServiceAccount,
  captureServiceBootstrap,
  OAATH_SERVICE_BOOTSTRAP_VERSION,
  OAATH_WORKSPACE_ACCOUNT_CONTEXT_VERSION,
  parseServiceBootstrap,
  parseWorkspaceAccountContext,
} from "./service-bootstrap.js";
export type {
  CanonicalEip712Array,
  CanonicalEip712Field,
  CanonicalEip712Object,
  CanonicalEip712TypedData,
  CanonicalEip712Value,
  Eip712OwnerSigningRequest,
  Eip712SigningPurpose,
  OwnerSigningReplayFacts,
  OwnerSigningRequest,
  OwnerSigningRequestSigner,
  RawDigestOwnerSigningRequest,
} from "./signing-request.js";
export {
  captureCanonicalEip712TypedData,
  captureOwnerSigningRequest,
  encodeOwnerSigningRequest,
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  OAATH_OWNER_SIGNING_REQUEST_HASH_DOMAIN,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  parseCanonicalEip712TypedData,
  parseOwnerSigningRequest,
} from "./signing-request.js";
export {
  classifyUserOperationError,
  type EntryPointFailureCode,
  OaathUserOperationError,
  parseUserOperationFailure,
  readUserOperationFailure,
  serializeUserOperationFailure,
  type UserOperationFailure,
  type UserOperationFailureCode,
  type UserOperationFailureStage,
} from "./user-operation-error.js";
export type { ValidationGasDiagnostic } from "./validation-diagnostic.js";
export {
  captureValidationGasDiagnostic,
  readValidationGasDiagnostic,
  validationGasDiagnosticMessage,
} from "./validation-diagnostic.js";
