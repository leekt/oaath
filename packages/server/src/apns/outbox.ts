/**
 * EXPERIMENTAL PREVIEW — at-least-once APNs delivery outbox: retry schedule and
 * dead-lettering.
 *
 * ```text
 * state and owner        one delivery record per operation id owns "was this
 *                        push settled?"; the transport owns one attempt only
 * persisted evidence     the record: state, attempts, availableAt, lease, and
 *                        the last classified outcome kind
 * resource occupied?     yes: a lease occupies the record until it expires or
 *                        settles, so two workers never attempt it concurrently
 * retry positively safe? yes, and only here: a push is at-least-once, so a
 *                        duplicate is collapsed by `apns-collapse-id`, never
 *                        suppressed by pretending an unproven send succeeded
 * transitions            pending -> pending(retrying) | delivered |
 *                        dead-lettered. Both terminal states are final.
 * crash/reload           a crashed worker's lease expires and the record is
 *                        leasable again; attempts already counted stay counted
 * cleanup owner          the lease holder settles; an abandoned lease is
 *                        reclaimed by expiry, never by another worker's write
 * ```
 *
 * `rejected` dead-letters immediately: Apple refused this device token, and
 * retrying a refusal is how an outbox spins forever. `unreadable` and
 * `unavailable` are retried on the schedule, which is data (`APNS_RETRY_BACKOFF_MS`)
 * so nothing here sleeps or owns a timer.
 *
 * The contract is deliberately its own, not new methods on `RelayTransaction`:
 * a preview surface may not widen the relay's core durable contract, and every
 * store implementation would then owe it. The memory implementation matches the
 * relay store's row-lock semantics; a PostgreSQL table is deferred until the
 * preview is qualified, which is why the schema module is untouched.
 *
 * @author taek <leekt216@gmail.com>
 */

import { type CaptureContext, exactRecord } from "@oaath/protocol";
import { randomIdentifier } from "../authorization/challenge.js";
import { relayFailure } from "../relay/errors.js";
import { boundedText, canonicalIdentifier, timestamp } from "../store/records.js";
import { APNS_PAYLOAD_MAX_BYTES } from "./sender.js";
import type { ApnsDeliveryOutcome } from "./transport.js";

export const OAATH_APNS_DELIVERY_RECORD_VERSION = "oaath.apns-delivery-record/v1" as const;

/**
 * Retry delays in milliseconds. One more attempt than there are delays, then the
 * record is dead-lettered.
 */
export const APNS_RETRY_BACKOFF_MS: readonly number[] = Object.freeze([1_000, 5_000, 30_000]);

const MAX_DEVICE_TOKEN = 200;
const UNREADABLE = "relay_record_unreadable" as const;

export type ApnsDeliveryState = "pending" | "delivered" | "dead-lettered";

export interface ApnsDeliveryRecord {
  readonly version: typeof OAATH_APNS_DELIVERY_RECORD_VERSION;
  /** Stable operation id from the phone projection. One delivery per operation. */
  readonly operationId: string;
  readonly deviceToken: string;
  /** The exact bytes to send. Opaque here; the sender built and bounded it. */
  readonly payload: string;
  readonly state: ApnsDeliveryState;
  /** Settled attempts, including the one that reached a terminal state. */
  readonly attempts: number;
  readonly createdAt: number;
  /** Earliest next attempt. Backoff is data; nothing in this module waits. */
  readonly availableAt: number;
  /** Non-null only while leased, and held by exactly one worker. */
  readonly leaseId: string | null;
  readonly leaseExpiresAt: number | null;
  /** Non-null exactly for the two terminal states. */
  readonly settledAt: number | null;
  /** Last classified transport outcome. Never Apple's prose. */
  readonly lastOutcome: ApnsDeliveryOutcome["kind"] | null;
}

export type ApnsSettleResult =
  | Readonly<{ settlement: "delivered" | "retrying" | "dead-lettered"; record: ApnsDeliveryRecord }>
  /** The lease is not the current one: a slower worker lost the record. */
  | Readonly<{ settlement: "stale" }>;

export interface ApnsEnqueueInput {
  readonly operationId: string;
  readonly deviceToken: string;
  readonly payload: string;
  readonly now: number;
}

export interface ApnsLeaseInput {
  readonly now: number;
  readonly leaseMs: number;
}

export interface ApnsSettleInput {
  readonly operationId: string;
  readonly leaseId: string;
  readonly outcome: ApnsDeliveryOutcome;
  readonly now: number;
}

export interface ApnsOutbox {
  /** False when the operation is already enqueued. One push per operation. */
  enqueue(input: ApnsEnqueueInput): Promise<boolean>;
  /**
   * Leases the next due pending record exclusively, under the same row-lock
   * semantics as the relay store, or `undefined` when nothing is due.
   */
  leaseNext(input: ApnsLeaseInput): Promise<ApnsDeliveryRecord | undefined>;
  settle(input: ApnsSettleInput): Promise<ApnsSettleResult>;
  read(operationId: string): Promise<ApnsDeliveryRecord | undefined>;
}

function deliveryState(value: unknown): ApnsDeliveryState {
  if (value === "pending" || value === "delivered" || value === "dead-lettered") return value;
  return relayFailure(UNREADABLE, "apns delivery state is unsupported");
}

function outcomeKind(value: unknown): ApnsDeliveryOutcome["kind"] | null {
  if (value === null) return null;
  if (
    value === "delivered" ||
    value === "rejected" ||
    value === "unreadable" ||
    value === "unavailable"
  ) {
    return value;
  }
  return relayFailure(UNREADABLE, "apns delivery outcome is unsupported");
}

function attempts(value: unknown): number {
  const count = timestamp(value, "attempts", UNREADABLE);
  if (count > APNS_RETRY_BACKOFF_MS.length + 1) {
    return relayFailure(UNREADABLE, "apns delivery attempts exceed the schedule");
  }
  return count;
}

function nullableIdentifier(value: unknown, label: string): string | null {
  return value === null ? null : canonicalIdentifier(value, label, UNREADABLE);
}

function nullableTimestamp(value: unknown, label: string): number | null {
  return value === null ? null : timestamp(value, label, UNREADABLE);
}

/** Durable storage is a trust boundary, including in memory. */
export function parseApnsDeliveryRecord(value: unknown): ApnsDeliveryRecord {
  const context: CaptureContext = new WeakSet();
  const record = exactRecord(
    value,
    [
      "version",
      "operationId",
      "deviceToken",
      "payload",
      "state",
      "attempts",
      "createdAt",
      "availableAt",
      "leaseId",
      "leaseExpiresAt",
      "settledAt",
      "lastOutcome",
    ],
    "apns delivery record",
    context,
    (message) => relayFailure(UNREADABLE, message),
  );
  if (record.version !== OAATH_APNS_DELIVERY_RECORD_VERSION) {
    return relayFailure(UNREADABLE, "apns delivery record version is unsupported");
  }
  return Object.freeze({
    version: OAATH_APNS_DELIVERY_RECORD_VERSION,
    operationId: canonicalIdentifier(record.operationId, "operationId", UNREADABLE),
    deviceToken: boundedText(record.deviceToken, MAX_DEVICE_TOKEN, "deviceToken", UNREADABLE),
    payload: boundedText(record.payload, APNS_PAYLOAD_MAX_BYTES, "payload", UNREADABLE),
    state: deliveryState(record.state),
    attempts: attempts(record.attempts),
    createdAt: timestamp(record.createdAt, "createdAt", UNREADABLE),
    availableAt: timestamp(record.availableAt, "availableAt", UNREADABLE),
    leaseId: nullableIdentifier(record.leaseId, "leaseId"),
    leaseExpiresAt: nullableTimestamp(record.leaseExpiresAt, "leaseExpiresAt"),
    settledAt: nullableTimestamp(record.settledAt, "settledAt"),
    lastOutcome: outcomeKind(record.lastOutcome),
  });
}

function settled(
  record: ApnsDeliveryRecord,
  nextState: Exclude<ApnsDeliveryState, "pending">,
  kind: ApnsDeliveryOutcome["kind"],
  now: number,
): ApnsDeliveryRecord {
  return Object.freeze({
    ...record,
    state: nextState,
    attempts: record.attempts + 1,
    leaseId: null,
    leaseExpiresAt: null,
    settledAt: now,
    lastOutcome: kind,
  });
}

/**
 * Process-local outbox with the durable contract's semantics. It survives no
 * restart: use it for local development and tests only.
 *
 * ponytail: a linear scan picks the next due record and one map holds the queue.
 * Both are fine for a preview push queue; index by `availableAt` only if a
 * deployment ever runs enough of them to notice.
 */
export function createMemoryApnsOutbox(
  backoffMs: readonly number[] = APNS_RETRY_BACKOFF_MS,
): ApnsOutbox {
  const rows = new Map<string, unknown>();
  const load = (operationId: string): ApnsDeliveryRecord | undefined => {
    const stored = rows.get(operationId);
    return stored === undefined ? undefined : parseApnsDeliveryRecord(stored);
  };

  return Object.freeze({
    async enqueue(input: ApnsEnqueueInput): Promise<boolean> {
      const operationId = canonicalIdentifier(input.operationId, "operationId", UNREADABLE);
      if (rows.has(operationId)) return false;
      rows.set(
        operationId,
        Object.freeze({
          version: OAATH_APNS_DELIVERY_RECORD_VERSION,
          operationId,
          deviceToken: boundedText(input.deviceToken, MAX_DEVICE_TOKEN, "deviceToken", UNREADABLE),
          payload: boundedText(input.payload, APNS_PAYLOAD_MAX_BYTES, "payload", UNREADABLE),
          state: "pending",
          attempts: 0,
          createdAt: timestamp(input.now, "now", UNREADABLE),
          availableAt: input.now,
          leaseId: null,
          leaseExpiresAt: null,
          settledAt: null,
          lastOutcome: null,
        }),
      );
      return true;
    },

    async leaseNext(input: ApnsLeaseInput): Promise<ApnsDeliveryRecord | undefined> {
      const now = timestamp(input.now, "now", UNREADABLE);
      const leaseMs = timestamp(input.leaseMs, "leaseMs", UNREADABLE);
      for (const key of rows.keys()) {
        const record = load(key);
        if (!record || record.state !== "pending" || record.availableAt > now) continue;
        // A live lease is exclusive; an expired one is reclaimable, because its
        // holder may have crashed mid-attempt.
        if (record.leaseExpiresAt !== null && record.leaseExpiresAt > now) continue;
        const leased = Object.freeze({
          ...record,
          leaseId: randomIdentifier(),
          leaseExpiresAt: now + leaseMs,
        });
        rows.set(key, leased);
        return leased;
      }
      return undefined;
    },

    async settle(input: ApnsSettleInput): Promise<ApnsSettleResult> {
      const now = timestamp(input.now, "now", UNREADABLE);
      const record = load(input.operationId);
      // Terminal, unleased, or a lost lease: this worker's settlement is void.
      if (!record || record.state !== "pending" || record.leaseId !== input.leaseId) {
        return Object.freeze({ settlement: "stale" });
      }
      if (input.outcome.kind === "delivered") {
        const next = settled(record, "delivered", "delivered", now);
        rows.set(record.operationId, next);
        return Object.freeze({ settlement: "delivered", record: next });
      }
      if (input.outcome.kind === "rejected") {
        const next = settled(record, "dead-lettered", "rejected", now);
        rows.set(record.operationId, next);
        return Object.freeze({ settlement: "dead-lettered", record: next });
      }
      const attempt = record.attempts + 1;
      const delay = backoffMs[attempt - 1];
      if (delay === undefined) {
        const next = settled(record, "dead-lettered", input.outcome.kind, now);
        rows.set(record.operationId, next);
        return Object.freeze({ settlement: "dead-lettered", record: next });
      }
      const next: ApnsDeliveryRecord = Object.freeze({
        ...record,
        attempts: attempt,
        availableAt: now + delay,
        leaseId: null,
        leaseExpiresAt: null,
        lastOutcome: input.outcome.kind,
      });
      rows.set(record.operationId, next);
      return Object.freeze({ settlement: "retrying", record: next });
    },

    async read(operationId: string): Promise<ApnsDeliveryRecord | undefined> {
      return load(operationId);
    },
  });
}
