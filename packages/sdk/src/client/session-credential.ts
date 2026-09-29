/**
 * The one optional session setting shared by local and URL mode.
 *
 * Key kind and custody are settings, never separate entry points: omitting
 * `session` (or `{ kind: "ecdsa" }`) keeps the realm's own generated ECDSA
 * key in the custody the deployment declares; a `{ kind: "webauthn", ... }`
 * session is the caller's passkey, held in the browser. It is captured once at
 * configuration time, before any fetch, key, or storage exists.
 *
 * Custody is a deployment fact the service bootstrap owns. `custody` never
 * selects or overrides it; it only asserts what the application requires, and
 * a declaration that differs fails closed with
 * `oaath_client_capability_unsupported` (source `session_custody_unsupported`).
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { keccak256 } from "viem";
import { type WebAuthnKeyInput, webauthnKey } from "../kernel/key/webauthn.js";
import type { KeyProfile } from "../kernel/types.js";
import { clientFail, clientFailure } from "./errors.js";

/** Where the session key signs. The service deployment declares it. */
export type OaathSessionCustody = "browser" | "application-backend" | "oaath-hosted";

/**
 * The session key the owner approves. Omitted or `{ kind: "ecdsa" }`: a
 * generated ECDSA key in the deployment's custody. `{ kind: "webauthn", ... }`:
 * the caller's passkey signs in the browser; only its public credential is
 * ever persisted. `custody`, when present, is a requirement the deployment's
 * declared custody must equal.
 */
export type OaathSession =
  | { readonly kind?: "ecdsa"; readonly custody?: OaathSessionCustody }
  | ({ readonly kind: "webauthn"; readonly custody?: "browser" } & WebAuthnKeyInput);

/** A caller-held session: no local custody and no wrapping key to forget. */
export interface SuppliedSession {
  readonly deviceId: string;
  readonly sessionKey: Readonly<KeyProfile>;
}

export interface CapturedSession {
  /** Null means the realm's own generated ECDSA session. */
  readonly supplied: Readonly<SuppliedSession> | null;
  /** Null means no requirement: the deployment's declaration applies. */
  readonly custody: OaathSessionCustody | null;
}

const CUSTODIES: readonly unknown[] = Object.freeze([
  "browser",
  "application-backend",
  "oaath-hosted",
]);

/** The one structured refusal for a session custody the realm cannot serve. */
export function unsupportedSessionCustody(message: string): never {
  return clientFail("oaath_client_capability_unsupported", message, "session_custody_unsupported");
}

/**
 * A caller-held credential needs no local custody: the device identity
 * derives from its public material, so reload recreates the same binding and
 * the Grant record's operator credential is the only persisted session fact.
 */
export function captureSession(value: unknown, context: CaptureContext): Readonly<CapturedSession> {
  if (value === undefined) return Object.freeze({ supplied: null, custody: null });
  const fail = clientFailure("oaath_client_input_invalid");
  const record = captureRecord(value, "session", context, fail);
  let custody: OaathSessionCustody | null = null;
  if (Object.hasOwn(record, "custody")) {
    if (!CUSTODIES.includes(record.custody)) return fail("session custody is unsupported");
    custody = record.custody as OaathSessionCustody;
  }
  if (record.kind === undefined || record.kind === "ecdsa") {
    exactCapturedRecord(
      record,
      ["kind", "custody"].filter((key) => Object.hasOwn(record, key)),
      "session",
      fail,
    );
    return Object.freeze({ supplied: null, custody });
  }
  if (record.kind !== "webauthn") return fail("session kind is unsupported");
  if (custody !== null && custody !== "browser") {
    return unsupportedSessionCustody("a passkey session requires browser custody");
  }
  const { kind: _kind, custody: _custody, ...material } = record;
  let sessionKey: Readonly<KeyProfile>;
  try {
    sessionKey = webauthnKey(material as unknown as WebAuthnKeyInput);
  } catch {
    return fail("WebAuthn session credential is invalid");
  }
  return Object.freeze({
    supplied: Object.freeze({
      deviceId: `passkey-${keccak256(sessionKey.publicMaterial).slice(2, 34)}`,
      sessionKey,
    }),
    custody,
  });
}
