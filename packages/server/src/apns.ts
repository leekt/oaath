/**
 * `@oaath/server/apns` — EXPERIMENTAL PREVIEW Apple push surface.
 *
 * Preview means: no stability guarantee and no production qualification.
 * Production APNs, Apple provisioning, hosted failover, and KMS key rotation are
 * later qualification work.
 *
 * Node-only: provider-token signing needs `node:crypto`, and delivery runs over
 * an HTTP/2 session the deployment owns. The root and `./native` entries stay
 * platform-neutral.
 *
 * Credentials are an injected capability object. Nothing in `src/` reads
 * `process.env`.
 *
 * @author taek <leekt216@gmail.com>
 */

export type {
  ApnsDeliveryRecord,
  ApnsDeliveryState,
  ApnsEnqueueInput,
  ApnsLeaseInput,
  ApnsOutbox,
  ApnsSettleInput,
  ApnsSettleResult,
} from "./apns/outbox.js";
export {
  APNS_RETRY_BACKOFF_MS,
  createMemoryApnsOutbox,
  OAATH_APNS_DELIVERY_RECORD_VERSION,
  parseApnsDeliveryRecord,
} from "./apns/outbox.js";
export type {
  ApnsCredentials,
  ApnsNotification,
  ApnsNotificationInput,
  ApnsSender,
  CreateApnsSenderInput,
} from "./apns/sender.js";
export {
  APNS_BODY_LOC_KEY,
  APNS_PAYLOAD_MAX_BYTES,
  APNS_TITLE_LOC_KEY,
  APNS_TOKEN_MAX_REUSE_MS,
  APNS_TOKEN_MIN_REUSE_MS,
  createApnsSender,
  OAATH_APNS_PAYLOAD_VERSION,
} from "./apns/sender.js";
export type {
  ApnsDeliveryOutcome,
  ApnsSession,
  ApnsStream,
  SendApnsNotificationInput,
} from "./apns/transport.js";
export { sendApnsNotification } from "./apns/transport.js";
