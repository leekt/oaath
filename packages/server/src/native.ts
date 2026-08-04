/**
 * `@oaath/server/native` — EXPERIMENTAL PREVIEW phone-approval surface.
 *
 * Preview means: no stability guarantee and no production qualification. Real
 * iOS provisioning, Secure Enclave/WebAuthn, hosted failover, and production
 * operations are later qualification work.
 *
 * The relay handler exposes these use cases as preview HTTP routes
 * (`GET /native/projections/{operationId}`,
 * `POST /native/decisions/{operationId}`), pinned field-for-field by the strict
 * Swift decoders in `native/ios/Sources/OwnerPhone/`.
 *
 * Platform-neutral like the root entry: Fetch, WebCrypto, and injected ports
 * only. Apple delivery lives behind `@oaath/server/apns`.
 *
 * There is deliberately no `native/store.ts`: the relay's `RelayStore`
 * transaction contract already carries the whole saga. The authorization
 * decision record is the durable, terminal, one-shot saga state, so a preview
 * decision record and a preview store contract would both be second owners of a
 * fact the relay already owns.
 *
 * @author taek <leekt216@gmail.com>
 */

export type { OwnerPhoneDecision, SubmitOwnerPhoneDecisionInput } from "./native/decision.js";
export { submitOwnerPhoneDecision } from "./native/decision.js";
export type {
  OwnerPhonePushProjection,
  OwnerPhoneRequestProjection,
  OwnerPhoneScopeProjection,
  ProjectOwnerPhoneRequestInput,
} from "./native/projection.js";
export {
  NATIVE_DISPLAY_PAYLOAD_LENGTH,
  OAATH_NATIVE_PROJECTION_VERSION,
  OAATH_SIGNATURE_REQUEST_SCOPE_VERSION,
  projectOwnerPhoneRequest,
} from "./native/projection.js";
