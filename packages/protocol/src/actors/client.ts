/**
 * OAuth client, origin, and redirect binding.
 *
 * The binding is what an issuer compares an incoming authorization request
 * against, so redirect targets must be exact same-origin https URLs. No
 * wildcards, no prefix matching, no duplicates.
 *
 * @author taek <leekt216@gmail.com>
 */
import { capturedByProtocol, protocolFailure } from "../errors.js";
import { type ClientId, parseClientId } from "../ids.js";
import {
  type CaptureContext,
  type CaptureFailure,
  captureDenseArray,
  exactRecord,
} from "../internal/exact-record.js";
import { captureCanonicalHttpsUrl } from "./issuer.js";

export const OAATH_CLIENT_BINDING_VERSION = "oaath.client-binding/v1" as const;

const MAX_REDIRECT_URIS = 8;
const APPLICATION_NAME = /^[!-~](?: ?[!-~]){0,63}$/u;

export interface ClientBinding {
  readonly version: typeof OAATH_CLIENT_BINDING_VERSION;
  readonly clientId: ClientId;
  /** Canonical https web origin with no path. */
  readonly origin: string;
  /** Exact same-origin https redirect targets, in the order the client declared. */
  readonly redirectUris: readonly string[];
  readonly applicationName: string;
}

function captureRedirectUris(
  value: unknown,
  origin: string,
  context: CaptureContext,
  fail: CaptureFailure,
): readonly string[] {
  const entries = captureDenseArray(value, "client redirectUris", context, fail);
  if (entries.length < 1 || entries.length > MAX_REDIRECT_URIS) {
    return fail(`client redirectUris must hold 1 to ${MAX_REDIRECT_URIS} exact URLs`);
  }
  const captured: string[] = [];
  for (const entry of entries) {
    const uri = captureCanonicalHttpsUrl(entry, "client redirect URI", fail, true);
    if (!uri.startsWith(`${origin}/`) && uri !== origin) {
      return fail("client redirect URI must share the client origin");
    }
    if (captured.includes(uri)) return fail("client redirectUris must not repeat a URL");
    captured.push(uri);
  }
  return Object.freeze(captured);
}

export function captureClientBinding(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<ClientBinding> {
  const record = exactRecord(
    value,
    ["version", "clientId", "origin", "redirectUris", "applicationName"],
    "client binding",
    context,
    fail,
  );
  if (record.version !== OAATH_CLIENT_BINDING_VERSION) {
    return fail("client binding version is unsupported");
  }
  if (
    typeof record.applicationName !== "string" ||
    !APPLICATION_NAME.test(record.applicationName)
  ) {
    return fail("client applicationName must be a bounded single-line printable name");
  }
  const origin = captureCanonicalHttpsUrl(record.origin, "client origin", fail);
  return Object.freeze({
    version: OAATH_CLIENT_BINDING_VERSION,
    clientId: parseClientId(record.clientId, fail),
    origin,
    redirectUris: captureRedirectUris(record.redirectUris, origin, context, fail),
    applicationName: record.applicationName,
  });
}

export function parseClientBinding(value: unknown): Readonly<ClientBinding> {
  return capturedByProtocol(
    "client_binding_invalid",
    "client binding could not be captured safely",
    () => captureClientBinding(value, new WeakSet(), protocolFailure("client_binding_invalid")),
  );
}
