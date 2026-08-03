/**
 * EXPERIMENTAL PREVIEW — settle-once HTTP/2 request lifecycle for APNs.
 *
 * ```text
 * state and owner        one request stream; this function owns its single
 *                        settlement and nothing else
 * persisted evidence     none. The outbox owns durable delivery state.
 * resource occupied?     the stream, released on settlement
 * retry positively safe? not decided here: this transport never retries
 * transitions            open -> settled(delivered|rejected|unreadable|
 *                        unavailable), exactly once
 * crash/reload           nothing to recover: no state outlives the call
 * cleanup owner          the settlement path destroys the stream
 * ```
 *
 * One request, one settlement. Response, stream error, and timeout all race, and
 * the first to arrive wins; every later event is dropped. A timeout is
 * `unreadable`, not `unavailable`: the notification may well have been accepted,
 * so the send is unproven, and nothing here may treat it as retryable.
 *
 * Classification is closed and never derived from prose:
 *
 * ```text
 * delivered    HTTP 200
 * rejected     a definite Apple refusal with a readable `reason`
 * unavailable  429, 500, 503, or a stream that failed before any status
 * unreadable   timeout, missing/unparseable status, unreadable refusal body,
 *              or a stream that failed after the status arrived
 * ```
 *
 * The session is a port so tests drive a fake stream: no network is contacted.
 * `node:http2`'s `ClientHttp2Session` satisfies it structurally, which
 * `test/apns.test.ts` proves at compile time.
 *
 * @author taek <leekt216@gmail.com>
 */

import type { ApnsNotification } from "./sender.js";

/** Bounded refusal body. Apple's is tiny; anything larger is not read. */
const MAX_BODY_BYTES = 4096;
/** Apple's documented reasons are short ASCII words. */
const REASON = /^[A-Za-z]{1,64}$/u;

export type ApnsDeliveryOutcome =
  | Readonly<{ kind: "delivered"; apnsId: string | null }>
  | Readonly<{ kind: "rejected"; status: number; reason: string }>
  | Readonly<{ kind: "unreadable" }>
  | Readonly<{ kind: "unavailable" }>;

/**
 * The subset of an HTTP/2 client stream this transport uses. Every listener
 * payload is `unknown`, because a provider's response is hostile input until it
 * has been read defensively.
 */
export interface ApnsStream {
  on(event: "response", listener: (headers: unknown) => void): unknown;
  on(event: "data", listener: (chunk: unknown) => void): unknown;
  on(event: "end", listener: () => void): unknown;
  on(event: "error", listener: (error: unknown) => void): unknown;
  setTimeout(milliseconds: number, callback: () => void): unknown;
  end(data?: string): unknown;
  destroy(): unknown;
}

export interface ApnsSession {
  request(headers: Readonly<Record<string, string>>): ApnsStream;
}

export interface SendApnsNotificationInput {
  readonly session: ApnsSession;
  readonly notification: ApnsNotification;
  readonly timeoutMs: number;
}

function reasonOf(body: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object") return null;
  const reason: unknown = (parsed as Record<string, unknown>).reason;
  return typeof reason === "string" && REASON.test(reason) ? reason : null;
}

function classify(status: number | null, apnsId: string | null, body: string): ApnsDeliveryOutcome {
  if (status === 200) return Object.freeze({ kind: "delivered", apnsId });
  // Apple's back-pressure and its own faults are provider unavailability.
  if (status === null || status === 429 || status === 500 || status === 503) {
    return Object.freeze({ kind: status === null ? "unreadable" : "unavailable" });
  }
  const reason = reasonOf(body);
  // A refusal we cannot read is unreadable evidence, never a proven refusal.
  return reason === null
    ? Object.freeze({ kind: "unreadable" })
    : Object.freeze({ kind: "rejected", status, reason });
}

function headerText(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** Response headers are provider output: read them as data, never as a shape. */
function headerMap(headers: unknown): ReadonlyMap<string, unknown> {
  if (headers === null || typeof headers !== "object") return new Map();
  return new Map<string, unknown>(Object.entries(headers));
}

/**
 * Sends one notification and settles exactly once. It never retries, and it
 * never throws: every outcome, including an unopenable stream, is a classified
 * value the outbox decides on.
 */
export function sendApnsNotification(
  input: SendApnsNotificationInput,
): Promise<ApnsDeliveryOutcome> {
  return new Promise<ApnsDeliveryOutcome>((resolve) => {
    let stream: ApnsStream;
    try {
      stream = input.session.request(input.notification.headers);
    } catch {
      // Nothing was written, so nothing could have been delivered.
      resolve(Object.freeze({ kind: "unavailable" }));
      return;
    }

    let settled = false;
    let status: number | null = null;
    let apnsId: string | null = null;
    let body = "";

    const settle = (outcome: ApnsDeliveryOutcome): void => {
      if (settled) return;
      settled = true;
      try {
        stream.destroy();
      } catch {
        // Releasing the stream is cleanup: its failure never changes the outcome.
      }
      resolve(outcome);
    };

    stream.on("response", (headers) => {
      const map = headerMap(headers);
      const raw = map.get(":status");
      status = typeof raw === "number" ? raw : Number.parseInt(headerText(raw) ?? "", 10);
      if (!Number.isInteger(status)) status = null;
      apnsId = headerText(map.get("apns-id"));
    });
    stream.on("data", (chunk) => {
      if (body.length >= MAX_BODY_BYTES) return;
      body += typeof chunk === "string" ? chunk : String(chunk);
    });
    stream.on("end", () => {
      settle(classify(status, apnsId, body.slice(0, MAX_BODY_BYTES)));
    });
    stream.on("error", () => {
      // Before a status nothing reached Apple's decision; after one, we had a
      // decision we could not finish reading.
      settle(Object.freeze({ kind: status === null ? "unavailable" : "unreadable" }));
    });
    stream.setTimeout(input.timeoutMs, () => {
      // A timeout is not an absence: the notification may have been accepted.
      settle(Object.freeze({ kind: "unreadable" }));
    });
    stream.end(input.notification.payload);
  });
}
