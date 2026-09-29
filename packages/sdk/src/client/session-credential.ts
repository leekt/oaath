/**
 * The one optional session-credential setting shared by local and URL mode.
 *
 * Key kind is a setting, never a separate entry point: omitting `session` (or
 * `{ kind: "ecdsa" }`) keeps the realm's own generated, wrapped ECDSA key; a
 * `{ kind: "webauthn", ... }` session is the caller's passkey. It is captured
 * once at configuration time, before any fetch or storage exists.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type CaptureContext, captureRecord, exactCapturedRecord } from "@oaath/protocol";
import { keccak256 } from "viem";
import { type WebAuthnKeyInput, webauthnKey } from "../kernel/key/webauthn.js";
import type { KeyProfile } from "../kernel/types.js";
import { clientFailure } from "./errors.js";

/**
 * The session credential the owner approves. Omitted or `{ kind: "ecdsa" }`:
 * the realm generates and wraps its own ECDSA key. `{ kind: "webauthn", ... }`:
 * the caller's passkey signs; only its public credential is ever persisted.
 */
export type OaathSession =
  | { readonly kind?: "ecdsa" }
  | ({ readonly kind: "webauthn" } & WebAuthnKeyInput);

/** A caller-held session: no local custody and no wrapping key to forget. */
export interface SuppliedSession {
  readonly deviceId: string;
  readonly sessionKey: Readonly<KeyProfile>;
}

/**
 * Null means the realm's own generated ECDSA session. A caller-held
 * credential needs no local custody: the device identity derives from its
 * public material, so reload recreates the same binding and the Grant
 * record's operator credential is the only persisted session fact.
 */
export function captureSession(
  value: unknown,
  context: CaptureContext,
): Readonly<SuppliedSession> | null {
  if (value === undefined) return null;
  const fail = clientFailure("oaath_client_input_invalid");
  const record = captureRecord(value, "session", context, fail);
  if (record.kind === undefined || record.kind === "ecdsa") {
    exactCapturedRecord(record, Object.hasOwn(record, "kind") ? ["kind"] : [], "session", fail);
    return null;
  }
  if (record.kind !== "webauthn") return fail("session kind is unsupported");
  const { kind: _kind, ...material } = record;
  let sessionKey: Readonly<KeyProfile>;
  try {
    sessionKey = webauthnKey(material as unknown as WebAuthnKeyInput);
  } catch {
    return fail("WebAuthn session credential is invalid");
  }
  return Object.freeze({
    deviceId: `passkey-${keccak256(sessionKey.publicMaterial).slice(2, 34)}`,
    sessionKey,
  });
}
