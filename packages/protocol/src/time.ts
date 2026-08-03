/**
 * Bounded canonical protocol time.
 *
 * OAAth times are Unix timestamps in whole seconds bounded by `uint48`,
 * matching the Grant policy validity window that reaches the chain. Fractional,
 * negative, negative-zero, non-number, and out-of-range values are rejected
 * rather than normalized; seconds are the only unit the protocol speaks.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type ProtocolContractErrorCode, protocolFailure } from "./errors.js";
import type { CaptureFailure } from "./internal/exact-record.js";

const TIME_CODE: ProtocolContractErrorCode = "protocol_time_invalid";
const timeFailure = protocolFailure(TIME_CODE);

/** Largest representable protocol timestamp, in seconds (`uint48`). */
export const MAX_PROTOCOL_TIMESTAMP = 2 ** 48 - 1;

declare const timeBrand: unique symbol;

/** Whole-second Unix timestamp in `[0, MAX_PROTOCOL_TIMESTAMP]`. */
export type Timestamp = number & { readonly [timeBrand]: "timestamp" };

/** Whole-second duration in `[0, MAX_PROTOCOL_TIMESTAMP]`. */
export type Duration = number & { readonly [timeBrand]: "duration" };

function boundedSeconds(value: unknown, label: string, fail: CaptureFailure): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0 ||
    value > MAX_PROTOCOL_TIMESTAMP
  ) {
    return fail(`${label} must be whole seconds in [0, ${MAX_PROTOCOL_TIMESTAMP}]`);
  }
  return value;
}

export function parseTimestamp(
  value: unknown,
  label = "timestamp",
  fail: CaptureFailure = timeFailure,
): Timestamp {
  return boundedSeconds(value, label, fail) as Timestamp;
}

export function parseDuration(
  value: unknown,
  label = "duration",
  fail: CaptureFailure = timeFailure,
): Duration {
  return boundedSeconds(value, label, fail) as Duration;
}

/** Inclusive-to-exclusive elapsed seconds; a backwards window is not a duration. */
export function durationBetween(
  earlier: Timestamp,
  later: Timestamp,
  label = "duration",
  fail: CaptureFailure = timeFailure,
): Duration {
  if (later < earlier) return fail(`${label} must not end before it starts`);
  return (later - earlier) as Duration;
}
