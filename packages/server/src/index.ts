/**
 * @oaath/server — durable authorization relay.
 *
 * Platform-neutral: this entry uses only Fetch, WebCrypto, and the ports the
 * deployment injects. PostgreSQL lives behind the `@oaath/server/postgres`
 * subpath.
 *
 * @author taek <leekt216@gmail.com>
 */

export type { ClaimEncryptedArtifactInput, ClaimedEncryptedArtifact } from "./artifact/claim.js";
export { claimEncryptedArtifact } from "./artifact/claim.js";
export { openArtifact, sealArtifact } from "./artifact/encrypt.js";
export { isCodeChallengeS256, verifyPkceS256 } from "./authorization/challenge.js";
export type {
  ConsumeAuthorizationCodeInput,
  ConsumedAuthorizationCode,
} from "./authorization/code.js";
export { consumeAuthorizationCode } from "./authorization/code.js";
export type {
  AuthorizationDecisionCommand,
  SubmitAuthorizationDecisionInput,
  SubmittedAuthorizationDecision,
} from "./authorization/decision.js";
export { submitAuthorizationDecision } from "./authorization/decision.js";
export type {
  AuthorizationState,
  CreateAuthorizationRequestInput,
  CreatedAuthorizationRequest,
  FetchAuthorizationRequestInput,
} from "./authorization/request.js";
export { createAuthorizationRequest, fetchAuthorizationRequest } from "./authorization/request.js";
export type { ResumeAuthorizationInput } from "./authorization/resume.js";
export { resumeAuthorization } from "./authorization/resume.js";
export type { RelayClock } from "./clock.js";
export type { RelayErrorCode } from "./relay/errors.js";
export { OaathRelayError, RELAY_ERROR_STATUS } from "./relay/errors.js";
export type { RelayHandler, RelayHandlerOptions } from "./relay/handler.js";
export { createRelayHandler } from "./relay/handler.js";
export type {
  RelayAuthentication,
  RelayCaller,
  RelayCallerRole,
} from "./security/authentication.js";
export type { RelayKms } from "./security/kms.js";
export type { RelayRateLimiter, RelayRateLimitInput } from "./security/rate-limit.js";
export { REDACTED, redactForLog, redactUrl } from "./security/redact.js";
export type { RelayStore, RelayTransaction } from "./store/interface.js";
export { createMemoryRelayStore } from "./store/memory.js";
export type {
  AuthorizationCodeRecord,
  AuthorizationDecisionOutcome,
  AuthorizationDecisionRecord,
  AuthorizationRequestRecord,
  EncryptedArtifactRecord,
} from "./store/records.js";
export {
  OAATH_AUTHORIZATION_CODE_RECORD_VERSION,
  OAATH_AUTHORIZATION_DECISION_RECORD_VERSION,
  OAATH_AUTHORIZATION_REQUEST_RECORD_VERSION,
  OAATH_ENCRYPTED_ARTIFACT_RECORD_VERSION,
} from "./store/records.js";
