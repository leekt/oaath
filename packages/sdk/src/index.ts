/**
 * The adopter surface: one constructor, the lifecycle handles it returns,
 * Login with OAAth (an identity step that needs none of the constructor's
 * configuration), and the one closed error vocabulary. Everything else — Kernel primitives,
 * custom-deployment ports, persistence adapters, deterministic test stores —
 * lives behind an explicit subpath (`@oaath/sdk/kernel`, `/advanced`,
 * `/persistence`, `/testing`) so the default import teaches exactly one
 * product path.
 *
 * @author taek <leekt216@gmail.com>
 */

export type {
  EntryPointFailureCode,
  OaathUserOperationError,
  UserOperationFailureCode,
  UserOperationFailureStage,
  ValidationGasDiagnostic,
} from "@oaath/protocol";
export type { OaathCallsReviewContract } from "./client/calls-review.js";
export { OAATH_CALLS_REVIEW_VERSION, parseOaathCallsReview } from "./client/calls-review.js";
export type { OaathChainDescriptor } from "./client/chain-descriptors.js";
export type {
  OaathConnectedEoaFallbackReview,
  OaathConnectedEoaPayer,
} from "./client/connected-eoa.js";
export type {
  OaathConnection,
  OaathPendingPermissionResult,
  OaathPermissionCallInput,
  OaathPermissionInput,
  OaathRequestPermissionInput,
} from "./client/connection.js";
export type { OaathClientErrorCode } from "./client/errors.js";
export { OaathClientError } from "./client/errors.js";
export type {
  OaathCallInput,
  OaathCallsReview,
  OaathGetOperationInput,
  OaathGrantHandle,
  OaathOperationLane,
  OaathReviewCallsInput,
  OaathSendCallsInput,
} from "./client/grant-handle.js";
export type {
  OaathApprovalOwner,
  OaathApprovalWallet,
  OaathWalletApprovalClient,
  OaathWalletApprovalReview,
  OaathWalletApprovals,
  OaathWalletOptions,
} from "./client/local-realm.js";
export type {
  OaathAuthorizationLauncher,
  OaathLogin,
  OaathLoginOptions,
  OaathLoginSigner,
} from "./client/oauth-login.js";
export { completeOAAthLogin, loginWithOAAth } from "./client/oauth-login.js";
export type { OaathOAuthApprovals, OaathOAuthOptions } from "./client/oauth-realm.js";
export type {
  OaathOperationExecution,
  OaathOperationHandle,
  OaathOperationLog,
  OaathOperationOutcome,
  OaathOperationReceipt,
  OaathOperationStatus,
} from "./client/operation-handle.js";
export type {
  OaathOwnerAccount,
  OaathOwnerCallsReview,
  OaathOwnerClient,
  OaathOwnerHandle,
  OaathOwnerKey,
  OaathOwnerOptions,
  OaathOwnerStores,
} from "./client/owner-realm.js";
export type { OaathServiceApprovals, OaathServiceOptions } from "./client/service-realm.js";
export type { OaathSession, OaathSessionCustody } from "./client/session-credential.js";
export type { OaathPayer, OaathPaymasterServicePayer } from "./client/sponsorship.js";
export type { OaathStoreBackend, OaathStores } from "./client/stores.js";
export type { Oaath } from "./create-oaath.js";
export { createOAAth } from "./create-oaath.js";
