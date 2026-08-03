/**
 * Bounded credential and URL redaction for diagnostics only.
 *
 * Nothing here shapes a response or a machine decision. Its only job is to make
 * an adopter's log line safe and finite: no authorization code, verifier, token,
 * artifact, ciphertext, credential-bearing URL, or unbounded provider blob.
 *
 * @author taek <leekt216@gmail.com>
 */

export const REDACTED = "[redacted]";
const UNREADABLE_URL = "[unreadable-url]";
const TRUNCATED = "[truncated]";

const MAX_TEXT = 128;
const MAX_DEPTH = 3;
const MAX_ENTRIES = 16;

/** Key names whose values are never safe to log, matched after normalization. */
const SENSITIVE_KEYS: ReadonlySet<string> = new Set([
  "apikey",
  "artifact",
  "authorization",
  "bearer",
  "ciphertext",
  "ciphertextref",
  "clientsecret",
  "code",
  "codechallenge",
  "codeverifier",
  "cookie",
  "credential",
  "idtoken",
  "key",
  "password",
  "plaintext",
  "privatekey",
  "secret",
  "session",
  "sessionkey",
  "setcookie",
  "signature",
  "token",
  "verifier",
]);

function normalizeKey(key: string): string {
  return key.toLowerCase().replaceAll(/[^a-z0-9]/gu, "");
}

function isUrlKey(normalized: string): boolean {
  return normalized.endsWith("url") || normalized.endsWith("uri");
}

function boundText(value: string): string {
  return value.length <= MAX_TEXT ? value : `${value.slice(0, MAX_TEXT)}${TRUNCATED}`;
}

/** Keeps scheme, host, and path. Drops userinfo, query, and fragment. */
export function redactUrl(value: unknown): string {
  if (typeof value !== "string") return UNREADABLE_URL;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return UNREADABLE_URL;
  }
  const port = url.port === "" ? "" : `:${url.port}`;
  return boundText(`${url.protocol}//${url.hostname}${port}${url.pathname}`);
}

function redactValue(value: unknown, depth: number): unknown {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
      return boundText(value);
    case "number":
      return Number.isFinite(value) ? value : String(value);
    case "boolean":
      return value;
    case "bigint":
      return boundText(value.toString());
    case "object":
      break;
    default:
      // Functions, symbols, and undefined carry no safe diagnostic value.
      return REDACTED;
  }
  if (depth >= MAX_DEPTH) return REDACTED;
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ENTRIES).map((item) => redactValue(item, depth + 1));
    return value.length > MAX_ENTRIES ? [...items, TRUNCATED] : items;
  }
  if (value instanceof Error) {
    // Provider and driver messages routinely embed credentials and payloads.
    return { name: boundText(value.name), message: REDACTED };
  }
  return redactRecord(value as Record<string, unknown>, depth);
}

function redactRecord(value: Record<string, unknown>, depth: number): Record<string, unknown> {
  const redacted: Record<string, unknown> = {};
  let entries = 0;
  for (const key of Object.keys(value)) {
    if (entries >= MAX_ENTRIES) {
      redacted[TRUNCATED] = true;
      break;
    }
    entries += 1;
    const normalized = normalizeKey(key);
    if (SENSITIVE_KEYS.has(normalized)) {
      redacted[key] = REDACTED;
    } else if (isUrlKey(normalized)) {
      redacted[key] = redactUrl(value[key]);
    } else {
      redacted[key] = redactValue(value[key], depth + 1);
    }
  }
  return redacted;
}

/** Returns a bounded, credential-free projection safe to hand to a logger. */
export function redactForLog(value: unknown): unknown {
  return redactValue(value, 0);
}
