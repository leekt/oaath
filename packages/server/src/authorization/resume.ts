/**
 * Resume: fresh authentication plus a grant recovery read.
 *
 * Resume never transitions anything and never re-releases a code or an artifact.
 * The caller re-authenticates on every call, and receives only enough state to
 * decide whether its own grant work is still valid.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type RelayClock, relayNow } from "../clock.js";
import type { RelayCaller } from "../security/authentication.js";
import type { RelayStore } from "../store/interface.js";
import { withRelayTransaction } from "../store/interface.js";
import { type AuthorizationState, readAuthorizationState } from "./request.js";

export interface ResumeAuthorizationInput {
  readonly store: RelayStore;
  readonly clock: RelayClock;
  /** Freshly authenticated `client` caller; only the bound client may resume. */
  readonly caller: RelayCaller;
  readonly requestId: string;
}

export function resumeAuthorization(input: ResumeAuthorizationInput): Promise<AuthorizationState> {
  const now = relayNow(input.clock);
  return withRelayTransaction(input.store, (transaction) =>
    readAuthorizationState(
      transaction,
      input.requestId,
      now,
      (request) => request.clientId === input.caller.clientId,
    ),
  );
}
