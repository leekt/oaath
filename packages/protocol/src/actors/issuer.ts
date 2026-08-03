/**
 * Issuer identity and the canonical https URL rules the whole protocol uses.
 *
 * A canonical OAAth URL is `https`, has a lowercase host, no credentials, no
 * default port, no query, no fragment, and no trailing slash. Non-canonical
 * input is rejected, never rewritten, so one issuer has exactly one string.
 *
 * @author taek <leekt216@gmail.com>
 */
import { capturedByProtocol, protocolFailure } from "../errors.js";
import { type CaptureContext, type CaptureFailure, exactRecord } from "../internal/exact-record.js";

export const OAATH_ISSUER_VERSION = "oaath.issuer/v1" as const;

const MAX_URL_LENGTH = 2_048;

export interface IssuerIdentity {
  readonly version: typeof OAATH_ISSUER_VERSION;
  /** Canonical https URL, for example `https://issuer.example.com`. */
  readonly url: string;
}

/**
 * Captures one canonical https URL. `allowPath` distinguishes an issuer or
 * redirect URL, which may carry a path, from a bare web origin, which may not.
 */
export function captureCanonicalHttpsUrl(
  value: unknown,
  label: string,
  fail: CaptureFailure,
  allowPath = false,
): string {
  if (typeof value !== "string" || value.length > MAX_URL_LENGTH) {
    return fail(`${label} must be a bounded canonical https URL`);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return fail(`${label} must be a bounded canonical https URL`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    (!allowPath && parsed.pathname !== "/")
  ) {
    return fail(`${label} must be a bounded canonical https URL`);
  }
  const canonical = parsed.pathname === "/" ? parsed.origin : `${parsed.origin}${parsed.pathname}`;
  if (value !== canonical || canonical.endsWith("/")) {
    return fail(`${label} must already be in canonical form`);
  }
  return canonical;
}

export function captureIssuerIdentity(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<IssuerIdentity> {
  const record = exactRecord(value, ["version", "url"], "issuer identity", context, fail);
  if (record.version !== OAATH_ISSUER_VERSION)
    return fail("issuer identity version is unsupported");
  return Object.freeze({
    version: OAATH_ISSUER_VERSION,
    url: captureCanonicalHttpsUrl(record.url, "issuer url", fail, true),
  });
}

export function parseIssuerIdentity(value: unknown): Readonly<IssuerIdentity> {
  return capturedByProtocol("issuer_invalid", "issuer identity could not be captured safely", () =>
    captureIssuerIdentity(value, new WeakSet(), protocolFailure("issuer_invalid")),
  );
}
