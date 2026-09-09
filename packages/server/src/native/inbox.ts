/**
 * Read-only owner inbox derived from retained relay requests and decisions.
 * No delivery state, lease or second queue is persisted. Recreating the service
 * reads the same pending requests; deciding or expiring one removes it from the
 * next listing. A summary is discovery only: consent/decision checks current state.
 */
import { type RelayClock, relayNow } from "../clock.js";
import { relayFailure } from "../relay/errors.js";
import type { RelayCaller } from "../security/authentication.js";
import { type RelayStore, withRelayTransaction } from "../store/interface.js";
import { type OwnerPhonePushProjection, ownerPhoneDisplayPayload } from "./projection.js";

export const OAATH_NATIVE_INBOX_VERSION = "oaath.native-inbox/v1" as const;
const INBOX_LIMIT = 20;

export interface OwnerPhoneInbox {
  readonly version: typeof OAATH_NATIVE_INBOX_VERSION;
  readonly requests: readonly Readonly<OwnerPhonePushProjection>[];
}

/** The store owns transaction resources; this read prepares, signs and submits nothing. */
export async function listOwnerPhoneRequests(input: {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  readonly caller: RelayCaller;
}): Promise<Readonly<OwnerPhoneInbox>> {
  if (input.caller.role !== "owner")
    return relayFailure("relay_forbidden", "only an owner may read the inbox");
  const now = relayNow(input.clock);
  const requests = await withRelayTransaction(input.store, (transaction) =>
    transaction.listPendingOwnerRequests(input.caller.subject, now, INBOX_LIMIT),
  );
  if (requests.length > INBOX_LIMIT)
    return relayFailure("relay_record_unreadable", "owner inbox is unbounded");
  return Object.freeze({
    version: OAATH_NATIVE_INBOX_VERSION,
    requests: Object.freeze(
      await Promise.all(
        requests.map(async (request) => {
          if (request.ownerSubject !== input.caller.subject || request.expiresAt <= now) {
            return relayFailure(
              "relay_record_unreadable",
              "pending request does not match this owner inbox",
            );
          }
          return Object.freeze({
            operationId: request.operationId,
            expiresAt: request.expiresAt,
            displayPayload: await ownerPhoneDisplayPayload(
              request.ownerSubject,
              request.operationId,
            ),
          });
        }),
      ),
    ),
  });
}
