/**
 * The adopter surface: one constructor, the lifecycle handles it returns, and
 * the one closed error vocabulary. Everything else — Kernel primitives,
 * custom-deployment ports, persistence adapters, deterministic test stores —
 * lives behind an explicit subpath (`@oaath/sdk/kernel`, `/advanced`,
 * `/persistence`, `/testing`) so the default import teaches exactly one
 * product path.
 *
 * @author taek <leekt216@gmail.com>
 */

export type { ValidationGasDiagnostic } from "@oaath/protocol";
export type { OaathCallsReviewContract } from "./client/calls-review.js";
export { OAATH_CALLS_REVIEW_VERSION, parseOaathCallsReview } from "./client/calls-review.js";
export type {
  OaathConnectedEoaFallbackReview,
  OaathConnectedEoaPayer,
} from "./client/connected-eoa.js";
export type {
  OaathConnection,
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
  OaathApprovalWallet,
  OaathWalletApprovalClient,
  OaathWalletApprovalReview,
  OaathWalletApprovals,
  OaathWalletOptions,
} from "./client/local-realm.js";
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
  OaathOwnerOptions,
} from "./client/owner-realm.js";
export type { OaathServiceApprovals, OaathServiceOptions } from "./client/service-realm.js";
export type { OaathSession } from "./client/session-credential.js";
export type { OaathPayer, OaathPaymasterServicePayer } from "./client/sponsorship.js";
export type { Oaath } from "./create-oaath.js";
export { createOAAth } from "./create-oaath.js";
