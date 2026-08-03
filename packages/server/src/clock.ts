/**
 * Injected clock. Expiry is never read from `Date.now()` directly, so tests and
 * deployments own time.
 *
 * @author taek <leekt216@gmail.com>
 */

import { relayFailure } from "./relay/errors.js";
import { timestamp } from "./store/records.js";

export interface RelayClock {
  /** Milliseconds since the Unix epoch as a non-negative safe integer. */
  now(): number;
}

export function relayNow(clock: RelayClock): number {
  let value: unknown;
  try {
    value = clock.now();
  } catch {
    return relayFailure("relay_internal", "injected clock failed");
  }
  return timestamp(value, "clock time", "relay_internal");
}
