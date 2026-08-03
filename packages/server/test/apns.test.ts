/**
 * EXPERIMENTAL PREVIEW proofs for `@oaath/server/apns`: provider-token claim
 * shape and reuse window on a fake clock, the 4096-byte payload limit, the
 * transport's single settlement against a fake HTTP/2 stream, and the outbox's
 * lease exclusion, retry schedule, and dead-lettering.
 *
 * No network, no environment, no database: the ES256 key is generated here and
 * every stream event is driven by hand.
 *
 * @author taek <leekt216@gmail.com>
 */

import { createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import type { ClientHttp2Session } from "node:http2";
import { describe, expect, it } from "vitest";
import type { ApnsDeliveryRecord, ApnsOutbox, ApnsSettleResult } from "../src/apns/outbox.js";
import {
  APNS_RETRY_BACKOFF_MS,
  createMemoryApnsOutbox,
  OAATH_APNS_DELIVERY_RECORD_VERSION,
  parseApnsDeliveryRecord,
} from "../src/apns/outbox.js";
import type { ApnsCredentials, ApnsNotification } from "../src/apns/sender.js";
import {
  APNS_BODY_LOC_KEY,
  APNS_PAYLOAD_MAX_BYTES,
  APNS_TITLE_LOC_KEY,
  APNS_TOKEN_MAX_REUSE_MS,
  APNS_TOKEN_MIN_REUSE_MS,
  createApnsSender,
  OAATH_APNS_PAYLOAD_VERSION,
} from "../src/apns/sender.js";
import type { ApnsDeliveryOutcome, ApnsSession, ApnsStream } from "../src/apns/transport.js";
import { sendApnsNotification } from "../src/apns/transport.js";
import type { OwnerPhoneRequestProjection } from "../src/native/projection.js";
import { createTestClock, expectRelayFailure, type TestClock } from "./support.js";

/**
 * A real `node:http2` session satisfies the transport port. This assignment is
 * the whole proof: it is a compile-time check, so no session is ever opened.
 */
const HTTP2_CONFORMANCE: (session: ClientHttp2Session) => ApnsSession = (session) => session;

const DEVICE_TOKEN = "a".repeat(64);
const TIMEOUT_MS = 5_000;
const LEASE_MS = 30_000;

const PROJECTION: OwnerPhoneRequestProjection = Object.freeze({
  operationId: "operation-1",
  displayPayload: "Qx7-mB2c",
  expiresAt: 1_700_000_300_000,
});

function credentials(overrides: Partial<ApnsCredentials> = {}): ApnsCredentials {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return Object.freeze({
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    keyId: "ABC1234567",
    teamId: "TEAM123456",
    topic: "com.example.oaath",
    ...overrides,
  });
}

function sender(overrides: Partial<ApnsCredentials> = {}, clock: TestClock = createTestClock()) {
  return { clock, sender: createApnsSender({ credentials: credentials(overrides), clock }) };
}

interface DecodedToken {
  readonly header: Record<string, unknown>;
  readonly claims: Record<string, unknown>;
  readonly signature: Buffer;
  readonly signingInput: string;
}

function decodeToken(token: string): DecodedToken {
  const [header, claims, signature] = token.split(".");
  if (header === undefined || claims === undefined || signature === undefined) {
    throw new Error("provider token is not a compact JWS");
  }
  const json = (part: string): Record<string, unknown> =>
    JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
  return {
    header: json(header),
    claims: json(claims),
    signature: Buffer.from(signature, "base64url"),
    signingInput: `${header}.${claims}`,
  };
}

/** Deterministic fake stream: every event is emitted by the test, in order. */
interface FakeStream extends ApnsStream {
  emitResponse(headers: Record<string, unknown>): void;
  emitData(chunk: string): void;
  emitEnd(): void;
  emitError(): void;
  fireTimeout(): void;
  readonly sent: readonly string[];
  readonly destroys: number;
}

function fakeStream(): FakeStream {
  const listeners = new Map<string, (value: unknown) => void>();
  const sent: string[] = [];
  let timeout: (() => void) | null = null;
  let destroys = 0;
  const emit = (event: string, value?: unknown): void => {
    listeners.get(event)?.(value);
  };
  return {
    on(event: string, listener: (value: unknown) => void) {
      listeners.set(event, listener);
      return this;
    },
    setTimeout(_milliseconds: number, callback: () => void) {
      timeout = callback;
      return this;
    },
    end(data?: string) {
      if (data !== undefined) sent.push(data);
      return this;
    },
    destroy() {
      destroys += 1;
      return this;
    },
    emitResponse: (headers) => emit("response", headers),
    emitData: (chunk) => emit("data", chunk),
    emitEnd: () => emit("end"),
    emitError: () => emit("error", new Error("stream failed")),
    fireTimeout: () => timeout?.(),
    get sent() {
      return sent;
    },
    get destroys() {
      return destroys;
    },
  };
}

function fakeSession(stream: ApnsStream): ApnsSession & { readonly requests: number } {
  let requests = 0;
  return {
    request() {
      requests += 1;
      return stream;
    },
    get requests() {
      return requests;
    },
  };
}

function notification(): ApnsNotification {
  return sender().sender.notification({ deviceToken: DEVICE_TOKEN, projection: PROJECTION });
}

function enqueueInput(now: number) {
  return {
    operationId: PROJECTION.operationId,
    deviceToken: DEVICE_TOKEN,
    payload: notification().payload,
    now,
  };
}

describe("experimental APNs provider token", () => {
  it("signs the Apple claim shape with a verifiable ES256 signature", () => {
    const key = credentials();
    const clock = createTestClock();
    const decoded = decodeToken(createApnsSender({ credentials: key, clock }).providerToken());

    expect(decoded.header).toEqual({ alg: "ES256", kid: key.keyId, typ: "JWT" });
    expect(decoded.claims).toEqual({ iss: key.teamId, iat: Math.floor(clock.now() / 1000) });
    // JOSE r||s, not DER, or Apple rejects every push.
    expect(decoded.signature).toHaveLength(64);
    expect(
      verify(
        "sha256",
        Buffer.from(decoded.signingInput, "utf8"),
        { key: createPublicKey(key.privateKeyPem), dsaEncoding: "ieee-p1363" },
        decoded.signature,
      ),
    ).toBe(true);
  });

  it("reuses one token for the window and re-signs after it", () => {
    const { clock, sender: signer } = sender();
    const first = signer.providerToken();

    clock.advance(APNS_TOKEN_MIN_REUSE_MS - 1);
    expect(signer.providerToken()).toBe(first);

    clock.advance(APNS_TOKEN_MAX_REUSE_MS);
    const second = signer.providerToken();
    expect(second).not.toBe(first);
    expect(decodeToken(second).claims.iat).toBe(Math.floor(clock.now() / 1000));

    // A clock that moved backwards invalidates the cache instead of extending it.
    const backwards = createTestClock(1_000_000);
    const rewinding = createApnsSender({ credentials: credentials(), clock: backwards });
    const before = rewinding.providerToken();
    backwards.advance(-500_000);
    expect(rewinding.providerToken()).not.toBe(before);
  });

  it("fails closed on an unusable credential capability", async () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const clock = createTestClock();
    const rejected: readonly Partial<ApnsCredentials>[] = [
      { privateKeyPem: "not a pem" },
      { privateKeyPem: rsa.privateKey.export({ type: "pkcs8", format: "pem" }).toString() },
      { keyId: "lowercase1" },
      { teamId: "SHORT" },
      { topic: "com.example oaath" },
    ];
    for (const overrides of rejected) {
      await expectRelayFailure(
        async () => createApnsSender({ credentials: credentials(overrides), clock }),
        "relay_apns_credentials_invalid",
      );
    }
    await expectRelayFailure(
      async () =>
        createApnsSender({
          credentials: credentials(),
          clock,
          reuseWindowMs: APNS_TOKEN_MIN_REUSE_MS - 1,
        }),
      "relay_apns_credentials_invalid",
    );
    await expectRelayFailure(
      async () =>
        createApnsSender({
          credentials: Object.assign({ ...credentials() }, { extra: "field" }),
          clock,
        }),
      "relay_apns_credentials_invalid",
    );
  });
});

describe("experimental APNs payload", () => {
  it("carries the operation and a localized match code, never permission detail", () => {
    const built = notification();
    const payload: unknown = JSON.parse(built.payload);

    expect(payload).toEqual({
      aps: {
        alert: {
          "title-loc-key": APNS_TITLE_LOC_KEY,
          "loc-key": APNS_BODY_LOC_KEY,
          "loc-args": [PROJECTION.displayPayload],
        },
        sound: "default",
      },
      oaath: {
        version: OAATH_APNS_PAYLOAD_VERSION,
        operationId: PROJECTION.operationId,
        expiresAt: PROJECTION.expiresAt,
      },
    });
    for (const secret of ["erc20", "scope", "permission", "redirect", "subject"]) {
      expect(built.payload.toLowerCase()).not.toContain(secret);
    }
    expect(built.headers["apns-topic"]).toBe("com.example.oaath");
    expect(built.headers["apns-collapse-id"]).toBe(PROJECTION.operationId);
    expect(built.headers["apns-push-type"]).toBe("alert");
    expect(built.headers[":path"]).toBe(`/3/device/${DEVICE_TOKEN}`);
    expect(built.headers.authorization).toMatch(/^bearer [\w-]+\.[\w-]+\.[\w-]+$/u);
  });

  it("refuses a payload over Apple's limit and a hostile projection", async () => {
    const { sender: signer } = sender();
    await expectRelayFailure(
      async () =>
        signer.notification({
          deviceToken: DEVICE_TOKEN,
          projection: { ...PROJECTION, displayPayload: "x".repeat(APNS_PAYLOAD_MAX_BYTES) },
        }),
      "relay_apns_payload_too_large",
    );
    const invalid: readonly OwnerPhoneRequestProjection[] = [
      { ...PROJECTION, displayPayload: "" },
      { ...PROJECTION, operationId: "x".repeat(65) },
      { ...PROJECTION, expiresAt: -1 },
    ];
    for (const projection of invalid) {
      await expectRelayFailure(
        async () => signer.notification({ deviceToken: DEVICE_TOKEN, projection }),
        "relay_request_invalid",
      );
    }
    for (const deviceToken of ["", "nothex".repeat(11), `${DEVICE_TOKEN}/../3/device/other`]) {
      await expectRelayFailure(
        async () => signer.notification({ deviceToken, projection: PROJECTION }),
        "relay_request_invalid",
      );
    }
  });
});

describe("experimental APNs transport", () => {
  it("settles once on a delivered response and never retries", async () => {
    const stream = fakeStream();
    const session = fakeSession(stream);
    const built = notification();
    const settled = sendApnsNotification({ session, notification: built, timeoutMs: TIMEOUT_MS });

    stream.emitResponse({ ":status": 200, "apns-id": "apns-1" });
    stream.emitEnd();
    // Every later event, including a failure, is dropped by the settled guard.
    stream.emitError();
    stream.fireTimeout();
    stream.emitEnd();

    expect(await settled).toEqual({ kind: "delivered", apnsId: "apns-1" });
    expect(session.requests).toBe(1);
    expect(stream.sent).toEqual([built.payload]);
    expect(stream.destroys).toBe(1);
  });

  it("classifies Apple's refusals, back-pressure, and unreadable evidence", async () => {
    const cases: readonly Readonly<{
      status: number;
      body: string;
      expected: Record<string, unknown>;
    }>[] = [
      {
        status: 410,
        body: '{"reason":"Unregistered"}',
        expected: { kind: "rejected", status: 410, reason: "Unregistered" },
      },
      {
        status: 400,
        body: '{"reason":"BadDeviceToken"}',
        expected: { kind: "rejected", status: 400, reason: "BadDeviceToken" },
      },
      { status: 429, body: '{"reason":"TooManyRequests"}', expected: { kind: "unavailable" } },
      { status: 503, body: "", expected: { kind: "unavailable" } },
      { status: 500, body: "", expected: { kind: "unavailable" } },
      { status: 403, body: "not json", expected: { kind: "unreadable" } },
      { status: 403, body: '{"reason":"has spaces"}', expected: { kind: "unreadable" } },
    ];
    for (const testCase of cases) {
      const stream = fakeStream();
      const settled = sendApnsNotification({
        session: fakeSession(stream),
        notification: notification(),
        timeoutMs: TIMEOUT_MS,
      });
      stream.emitResponse({ ":status": String(testCase.status) });
      stream.emitData(testCase.body);
      stream.emitEnd();
      expect(await settled).toEqual(testCase.expected);
    }
  });

  it("treats a timeout as unreadable and a pre-status failure as unavailable", async () => {
    const timedOut = fakeStream();
    const timeout = sendApnsNotification({
      session: fakeSession(timedOut),
      notification: notification(),
      timeoutMs: TIMEOUT_MS,
    });
    timedOut.fireTimeout();
    // A timeout never proves absence, so it is never a rejection.
    expect(await timeout).toEqual({ kind: "unreadable" });

    const broken = fakeStream();
    const early = sendApnsNotification({
      session: fakeSession(broken),
      notification: notification(),
      timeoutMs: TIMEOUT_MS,
    });
    broken.emitError();
    expect(await early).toEqual({ kind: "unavailable" });

    const late = fakeStream();
    const interrupted = sendApnsNotification({
      session: fakeSession(late),
      notification: notification(),
      timeoutMs: TIMEOUT_MS,
    });
    late.emitResponse({ ":status": 200 });
    late.emitError();
    expect(await interrupted).toEqual({ kind: "unreadable" });

    const missing = fakeStream();
    const noStatus = sendApnsNotification({
      session: fakeSession(missing),
      notification: notification(),
      timeoutMs: TIMEOUT_MS,
    });
    missing.emitResponse({ "apns-id": "apns-2" });
    missing.emitEnd();
    expect(await noStatus).toEqual({ kind: "unreadable" });
  });

  it("reports an unopenable stream without sending anything", async () => {
    const outcome = await sendApnsNotification({
      session: {
        request() {
          throw new Error("session is closed");
        },
      },
      notification: notification(),
      timeoutMs: TIMEOUT_MS,
    });
    expect(outcome).toEqual({ kind: "unavailable" });
    expect(HTTP2_CONFORMANCE).toBeTypeOf("function");
  });
});

describe("experimental APNs outbox", () => {
  it("enqueues one delivery per operation", async () => {
    const outbox = createMemoryApnsOutbox();
    expect(await outbox.enqueue(enqueueInput(1_000))).toBe(true);
    expect(await outbox.enqueue(enqueueInput(2_000))).toBe(false);
    expect(await outbox.read(PROJECTION.operationId)).toMatchObject({
      version: OAATH_APNS_DELIVERY_RECORD_VERSION,
      state: "pending",
      attempts: 0,
      createdAt: 1_000,
      leaseId: null,
    });
    expect(await outbox.read("unknown")).toBeUndefined();
  });

  it("never leases one record twice at a time", async () => {
    const outbox = createMemoryApnsOutbox();
    await outbox.enqueue(enqueueInput(1_000));

    const leased = await outbox.leaseNext({ now: 1_000, leaseMs: LEASE_MS });
    expect(leased?.leaseId).toBeTypeOf("string");
    expect(await outbox.leaseNext({ now: 1_000, leaseMs: LEASE_MS })).toBeUndefined();
    expect(
      await outbox.leaseNext({ now: 1_000 + LEASE_MS - 1, leaseMs: LEASE_MS }),
    ).toBeUndefined();

    // A crashed worker's lease expires and the record becomes leasable again.
    const reclaimed = await outbox.leaseNext({ now: 1_000 + LEASE_MS, leaseMs: LEASE_MS });
    expect(reclaimed?.operationId).toBe(PROJECTION.operationId);
    expect(reclaimed?.leaseId).not.toBe(leased?.leaseId);

    // The lost lease may no longer settle the record.
    expect(
      await outbox.settle({
        operationId: PROJECTION.operationId,
        leaseId: leased?.leaseId ?? "",
        outcome: { kind: "delivered", apnsId: null },
        now: 1_000 + LEASE_MS,
      }),
    ).toEqual({ settlement: "stale" });
  });

  async function leaseAndSettle(
    outbox: ApnsOutbox,
    now: number,
    outcome: ApnsDeliveryOutcome,
  ): Promise<ApnsSettleResult> {
    const leased = await outbox.leaseNext({ now, leaseMs: LEASE_MS });
    if (leased === undefined || leased.leaseId === null) throw new Error("expected a lease");
    return outbox.settle({
      operationId: leased.operationId,
      leaseId: leased.leaseId,
      outcome,
      now,
    });
  }

  it("settles delivered once and terminally", async () => {
    const outbox = createMemoryApnsOutbox();
    await outbox.enqueue(enqueueInput(1_000));
    const settled = await leaseAndSettle(outbox, 1_000, { kind: "delivered", apnsId: "apns-1" });

    expect(settled).toMatchObject({ settlement: "delivered" });
    expect(await outbox.read(PROJECTION.operationId)).toMatchObject({
      state: "delivered",
      attempts: 1,
      settledAt: 1_000,
      lastOutcome: "delivered",
      leaseId: null,
    });
    // Terminal means terminal: no further lease, no second settlement.
    expect(await outbox.leaseNext({ now: 2_000, leaseMs: LEASE_MS })).toBeUndefined();
  });

  it("dead-letters an Apple refusal immediately", async () => {
    const outbox = createMemoryApnsOutbox();
    await outbox.enqueue(enqueueInput(1_000));
    const settled = await leaseAndSettle(outbox, 1_000, {
      kind: "rejected",
      status: 410,
      reason: "Unregistered",
    });

    expect(settled).toMatchObject({ settlement: "dead-lettered" });
    expect(await outbox.read(PROJECTION.operationId)).toMatchObject({
      state: "dead-lettered",
      attempts: 1,
      lastOutcome: "rejected",
    });
  });

  it("retries unproven attempts on the schedule, then dead-letters", async () => {
    const outbox = createMemoryApnsOutbox();
    await outbox.enqueue(enqueueInput(0));
    let now = 0;

    for (const [index, delay] of APNS_RETRY_BACKOFF_MS.entries()) {
      const settled = await leaseAndSettle(outbox, now, { kind: "unavailable" });
      expect(settled).toMatchObject({ settlement: "retrying" });
      const record: ApnsDeliveryRecord | undefined = await outbox.read(PROJECTION.operationId);
      expect(record).toMatchObject({
        state: "pending",
        attempts: index + 1,
        availableAt: now + delay,
        leaseId: null,
        lastOutcome: "unavailable",
      });
      // Backoff is honored: nothing is leasable before the scheduled time.
      expect(await outbox.leaseNext({ now: now + delay - 1, leaseMs: LEASE_MS })).toBeUndefined();
      now += delay;
    }

    const dead = await leaseAndSettle(outbox, now, { kind: "unreadable" });
    expect(dead).toMatchObject({ settlement: "dead-lettered" });
    expect(await outbox.read(PROJECTION.operationId)).toMatchObject({
      state: "dead-lettered",
      attempts: APNS_RETRY_BACKOFF_MS.length + 1,
      lastOutcome: "unreadable",
    });
  });

  it("re-validates every durable read", async () => {
    const record = {
      version: OAATH_APNS_DELIVERY_RECORD_VERSION,
      operationId: PROJECTION.operationId,
      deviceToken: DEVICE_TOKEN,
      payload: notification().payload,
      state: "pending",
      attempts: 0,
      createdAt: 1_000,
      availableAt: 1_000,
      leaseId: null,
      leaseExpiresAt: null,
      settledAt: null,
      lastOutcome: null,
    };
    expect(parseApnsDeliveryRecord({ ...record })).toEqual(record);

    const rejected: readonly unknown[] = [
      undefined,
      null,
      "record",
      { ...record, version: "oaath.apns-delivery-record/v0" },
      { ...record, extra: "field" },
      { ...record, state: "sent" },
      { ...record, attempts: APNS_RETRY_BACKOFF_MS.length + 2 },
      { ...record, lastOutcome: "queued" },
      { ...record, createdAt: -1 },
      { ...record, leaseId: "not safe" },
    ];
    for (const value of rejected) {
      await expectRelayFailure(
        async () => parseApnsDeliveryRecord(value),
        "relay_record_unreadable",
      );
    }
  });
});
