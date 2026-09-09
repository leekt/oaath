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
 * `POST /native/decisions/{operationId}`), pinned field-for-field by the strict
 * Swift decoders in `native/ios/Sources/OwnerPhone/`.
 *
 * Platform-neutral like the root entry: Fetch, WebCrypto, and injected ports
 * only. Apple delivery lives behind `@oaath/server/apns`.
 *
 * Grant authorization reuses `RelayStore` and its terminal decision record;
 * it has no second native store. The revocation export only projects an
 * already-admitted immutable request. Its separate owner-operation queue,
 * HTTP decision route and execution are not implemented by this module.
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
