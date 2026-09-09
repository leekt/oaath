/**
 * `@oaath/server/native` — EXPERIMENTAL PREVIEW phone-approval surface.
 *
 * Preview means: no stability guarantee and no production qualification. Real
 * iOS provisioning, Secure Enclave/WebAuthn, hosted failover, and production
 * operations are later qualification work.
 *
 * The relay handler exposes these use cases as preview HTTP routes
 * (`GET /native/projections/{operationId}`,
 * `GET /native/permission-signing/{operationId}`,
 * `POST /native/decisions/{operationId}`,
 * `POST /native/revocation-decisions/{operationId}`), pinned field-for-field by the strict
 * Swift decoders in `native/ios/Sources/OwnerPhone/`.
 *
 * Platform-neutral like the root entry: Fetch, WebCrypto, and injected ports
 * only. Apple delivery lives behind `@oaath/server/apns`.
 *
 * Grant authorization reuses `RelayStore` and its terminal decision record;
 * it has no second native store. Revocation uses separate immutable request and
 * terminal decision records in RelayStore. Approval proves sealed custody only;
 * submission and onchain completion remain separate.
 *
 * @author taek <leekt216@gmail.com>
 */

export type { OwnerPhoneDecision, SubmitOwnerPhoneDecisionInput } from "./native/decision.js";
export { submitOwnerPhoneDecision } from "./native/decision.js";
export type {
  OwnerPhonePermissionApprovals,
  PreparedOwnerPhonePermissionApproval,
} from "./native/permission-approval.js";
export type {
  OwnerPhonePushProjection,
  OwnerPhoneRequestProjection,
  OwnerPhoneScopeProjection,
  ProjectOwnerPhoneRequestInput,
} from "./native/projection.js";
export {
  NATIVE_DISPLAY_PAYLOAD_LENGTH,
  OAATH_NATIVE_PROJECTION_VERSION,
  projectOwnerPhonePermissionSigning,
  projectOwnerPhoneRequest,
} from "./native/projection.js";
export type {
  OwnerPhoneRevocationDecision,
  OwnerPhoneRevocationScopeProjection,
} from "./native/revocation.js";
export { projectOwnerPhoneRevocation } from "./native/revocation.js";

export type { RequestOwnerPhoneRevocationInput } from "./revocation/service.js";
export {
  fetchOwnerPhoneRevocation,
  requestOwnerPhoneRevocation,
  submitOwnerPhoneRevocationDecision,
} from "./revocation/service.js";
