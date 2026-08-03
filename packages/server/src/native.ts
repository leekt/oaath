/**
 * `@oaath/server/native` — EXPERIMENTAL PREVIEW phone-approval surface.
 *
 * Preview means: no stability guarantee, no HTTP route, no production
 * qualification. Real iOS, Apple provisioning, Secure Enclave/WebAuthn, hosted
 * failover, and production operations are later qualification work.
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
  OwnerPhoneRequestProjection,
  ProjectOwnerPhoneRequestInput,
} from "./native/projection.js";
export { NATIVE_DISPLAY_PAYLOAD_LENGTH, projectOwnerPhoneRequest } from "./native/projection.js";
