/**
 * EXPERIMENTAL PREVIEW — Apple provider-token signing and APNs payload
 * construction.
 *
 * Preview means: no stability guarantee and no production qualification. Apple
 * provisioning, KMS key rotation, and production operations are later work.
 *
 * Credentials are an injected capability. This package reads no environment
 * variable anywhere in `src/`: a deployment hands over the key material it
 * already owns, and the repository's normal gates scrub `APNS_*`/`APPLE_*` out
 * of the test environment so nothing can drift into an implicit default.
 *
 * The injected capability is a trust boundary, so it is exact-captured once
 * here: unknown fields, a non-P-256 key, or a non-Apple key/team id fail closed
 * with `relay_apns_credentials_invalid`. The provider error is never surfaced,
 * because it can quote key material.
 *
 * Payloads stay opaque. Human text is a phone-side localization key, and the
 * only variable rendered is the projection's bounded match code. No permission,
 * scope, client, chain, or account detail is ever serialized: the payload
 * transits Apple.
 *
 * @author taek <leekt216@gmail.com>
 */

import { createPrivateKey, type KeyObject, sign } from "node:crypto";
import { type CaptureContext, exactRecord } from "@oaath/protocol";
import { type RelayClock, relayNow } from "../clock.js";
import type { OwnerPhonePushProjection } from "../native/projection.js";
import { relayFailure } from "../relay/errors.js";
import { canonicalIdentifier, timestamp } from "../store/records.js";

/** Apple's hard limit for an alert notification payload. */
export const APNS_PAYLOAD_MAX_BYTES = 4096;

export const OAATH_APNS_PAYLOAD_VERSION = "oaath.apns-payload/v1" as const;

/** Localization keys: the phone owns every word the owner reads. */
export const APNS_TITLE_LOC_KEY = "oaath_approval_title" as const;
export const APNS_BODY_LOC_KEY = "oaath_approval_body" as const;

/** Apple rejects a token older than one hour and re-signing more often than 20 minutes. */
export const APNS_TOKEN_MIN_REUSE_MS = 1_200_000;
export const APNS_TOKEN_MAX_REUSE_MS = 3_600_000;
const DEFAULT_REUSE_MS = 2_700_000;

const MAX_PEM_LENGTH = 8192;
/** `apns-collapse-id` is limited to 64 bytes. */
const MAX_COLLAPSE_ID = 64;
const APPLE_TEN_CHARACTER_ID = /^[A-Z0-9]{10}$/u;
const DEVICE_TOKEN = /^[0-9a-fA-F]{64,200}$/u;

const CREDENTIALS_INVALID = "relay_apns_credentials_invalid" as const;
const INVALID = "relay_request_invalid" as const;

export interface ApnsCredentials {
  /** PEM-encoded P-256 (`prime256v1`) private key from Apple. */
  readonly privateKeyPem: string;
  /** Apple key id (`kid`). */
  readonly keyId: string;
  /** Apple team id (`iss`). */
  readonly teamId: string;
  /** Bundle identifier used as `apns-topic`. */
  readonly topic: string;
}

export interface CreateApnsSenderInput {
  /** Injected capability object. Never sourced from `process.env`. */
  readonly credentials: ApnsCredentials;
  readonly clock: RelayClock;
  /** 20-60 minutes. Defaults to 45. */
  readonly reuseWindowMs?: number;
}

export interface ApnsNotificationInput {
  /** Lowercase or uppercase hex device token. */
  readonly deviceToken: string;
  /**
   * Only the opaque push subset is accepted: the payload transits Apple, so
   * the consent projection's client and scope detail must never reach here.
   */
  readonly projection: OwnerPhonePushProjection;
}

export interface ApnsNotification {
  readonly operationId: string;
  /** HTTP/2 request headers, including the `:method`/`:scheme`/`:path` pseudo-headers. */
  readonly headers: Readonly<Record<string, string>>;
  /** JSON body, already proven to be within `APNS_PAYLOAD_MAX_BYTES`. */
  readonly payload: string;
}

export interface ApnsSender {
  /** Signs lazily and reuses one token for the whole reuse window. */
  providerToken(): string;
  notification(input: ApnsNotificationInput): ApnsNotification;
}

function boundedPem(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > MAX_PEM_LENGTH) {
    return relayFailure(CREDENTIALS_INVALID, "privateKeyPem must be a bounded non-empty PEM");
  }
  return value;
}

/**
 * Bounded, but wide enough that an oversized display payload is a reachable
 * failure instead of an unprovable one: the 4096-byte payload check owns it.
 */
function boundedDisplayPayload(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > APNS_PAYLOAD_MAX_BYTES) {
    return relayFailure(INVALID, "displayPayload must be a bounded non-empty string");
  }
  return value;
}

function captureCredentials(value: unknown): ApnsCredentials {
  const context: CaptureContext = new WeakSet();
  const fail = (message: string): never => relayFailure(CREDENTIALS_INVALID, message);
  const record = exactRecord(
    value,
    ["privateKeyPem", "keyId", "teamId", "topic"],
    "apns credentials",
    context,
    fail,
  );
  const keyId = canonicalIdentifier(record.keyId, "keyId", CREDENTIALS_INVALID);
  const teamId = canonicalIdentifier(record.teamId, "teamId", CREDENTIALS_INVALID);
  if (!APPLE_TEN_CHARACTER_ID.test(keyId) || !APPLE_TEN_CHARACTER_ID.test(teamId)) {
    fail("keyId and teamId must be Apple ten-character identifiers");
  }
  return Object.freeze({
    // PEM carries newlines, so it is bounded by length only and validated by the
    // key parser rather than by the control-character text rules.
    privateKeyPem: boundedPem(record.privateKeyPem),
    keyId,
    teamId,
    // A topic reaches an HTTP/2 header, so it stays URL-safe by construction.
    topic: canonicalIdentifier(record.topic, "topic", CREDENTIALS_INVALID),
  });
}

function signingKey(privateKeyPem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: privateKeyPem, format: "pem" });
  } catch {
    // The parser error can quote key material; only the code leaves.
    return relayFailure(CREDENTIALS_INVALID, "privateKeyPem is not a readable PEM private key");
  }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    return relayFailure(CREDENTIALS_INVALID, "privateKeyPem must be a P-256 signing key");
  }
  return key;
}

function reuseWindow(value: number | undefined): number {
  if (value === undefined) return DEFAULT_REUSE_MS;
  const milliseconds = timestamp(value, "reuseWindowMs", CREDENTIALS_INVALID);
  if (milliseconds < APNS_TOKEN_MIN_REUSE_MS || milliseconds > APNS_TOKEN_MAX_REUSE_MS) {
    return relayFailure(CREDENTIALS_INVALID, "reuseWindowMs must be 20-60 minutes");
  }
  return milliseconds;
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function captureProjection(value: unknown): OwnerPhonePushProjection {
  const context: CaptureContext = new WeakSet();
  const fail = (message: string): never => relayFailure(INVALID, message);
  const record = exactRecord(
    value,
    ["operationId", "displayPayload", "expiresAt"],
    "owner phone projection",
    context,
    fail,
  );
  const operationId = canonicalIdentifier(record.operationId, "operationId", INVALID);
  if (operationId.length > MAX_COLLAPSE_ID) {
    fail("operationId must fit an apns-collapse-id");
  }
  return Object.freeze({
    operationId,
    displayPayload: boundedDisplayPayload(record.displayPayload),
    expiresAt: timestamp(record.expiresAt, "expiresAt", INVALID),
  });
}

export function createApnsSender(input: CreateApnsSenderInput): ApnsSender {
  const credentials = captureCredentials(input.credentials);
  const key = signingKey(credentials.privateKeyPem);
  const windowMs = reuseWindow(input.reuseWindowMs);
  let cached: Readonly<{ token: string; issuedAt: number }> | null = null;

  const providerToken = (): string => {
    const now = relayNow(input.clock);
    // A clock that moved backwards invalidates the cache rather than extending it.
    if (cached !== null && now >= cached.issuedAt && now - cached.issuedAt < windowMs) {
      return cached.token;
    }
    const signingInput = `${base64UrlJson({
      alg: "ES256",
      kid: credentials.keyId,
      typ: "JWT",
    })}.${base64UrlJson({ iss: credentials.teamId, iat: Math.floor(now / 1000) })}`;
    let signature: Buffer;
    try {
      // JOSE needs the raw r||s form, not the DER sequence node signs by default.
      signature = sign("sha256", Buffer.from(signingInput, "utf8"), {
        key,
        dsaEncoding: "ieee-p1363",
      });
    } catch {
      return relayFailure(CREDENTIALS_INVALID, "provider token could not be signed");
    }
    const token = `${signingInput}.${signature.toString("base64url")}`;
    cached = Object.freeze({ token, issuedAt: now });
    return token;
  };

  return Object.freeze({
    providerToken,
    notification(details: ApnsNotificationInput): ApnsNotification {
      const projection = captureProjection(details.projection);
      if (typeof details.deviceToken !== "string" || !DEVICE_TOKEN.test(details.deviceToken)) {
        // The token reaches the `:path` pseudo-header; only hex may get there.
        relayFailure(INVALID, "deviceToken must be a hex APNs device token");
      }
      const payload = JSON.stringify({
        aps: {
          alert: {
            "title-loc-key": APNS_TITLE_LOC_KEY,
            "loc-key": APNS_BODY_LOC_KEY,
            "loc-args": [projection.displayPayload],
          },
          sound: "default",
        },
        oaath: {
          version: OAATH_APNS_PAYLOAD_VERSION,
          operationId: projection.operationId,
          expiresAt: projection.expiresAt,
        },
      });
      if (Buffer.byteLength(payload, "utf8") > APNS_PAYLOAD_MAX_BYTES) {
        relayFailure("relay_apns_payload_too_large", "apns payload exceeds Apple's limit");
      }
      return Object.freeze({
        operationId: projection.operationId,
        payload,
        headers: Object.freeze({
          ":method": "POST",
          ":scheme": "https",
          ":path": `/3/device/${details.deviceToken}`,
          authorization: `bearer ${providerToken()}`,
          "apns-topic": credentials.topic,
          "apns-push-type": "alert",
          "apns-priority": "10",
          "apns-expiration": String(Math.floor(projection.expiresAt / 1000)),
          // One notification per operation, so a duplicate push collapses.
          "apns-collapse-id": projection.operationId,
        }),
      });
    },
  });
}
