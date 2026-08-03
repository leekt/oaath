/**
 * Redaction bounds. Diagnostics only: nothing here shapes a response.
 *
 * @author taek <leekt216@gmail.com>
 */

import { describe, expect, it } from "vitest";
import { REDACTED, redactForLog, redactUrl } from "../src/security/redact.js";

describe("redactUrl", () => {
  it("keeps only scheme, host, port, and path", () => {
    expect(
      redactUrl("https://user:secret@relay.example:8443/authorization/resume?code=abc#frag"),
    ).toBe("https://relay.example:8443/authorization/resume");
    expect(redactUrl("https://relay.example/callback?code=abc")).toBe(
      "https://relay.example/callback",
    );
  });

  it("refuses anything it cannot parse", () => {
    expect(redactUrl("not a url")).toBe("[unreadable-url]");
    expect(redactUrl(undefined)).toBe("[unreadable-url]");
    expect(redactUrl(42)).toBe("[unreadable-url]");
  });

  it("bounds a long path", () => {
    const redacted = redactUrl(`https://relay.example/${"a".repeat(400)}`);
    expect(redacted.endsWith("[truncated]")).toBe(true);
    expect(redacted.length).toBe(128 + "[truncated]".length);
  });
});

describe("redactForLog", () => {
  it("redacts credential-bearing keys however they are spelled", () => {
    expect(
      redactForLog({
        code: "authorization-code",
        code_verifier: "verifier",
        codeChallenge: "challenge",
        Authorization: "Bearer token",
        "set-cookie": "session=1",
        apiKey: "k",
        artifact: "plaintext",
        ciphertextRef: "ref",
        signature: "0xdead",
        privateKey: "0xbeef",
        requestId: "request-1",
      }),
    ).toEqual({
      code: REDACTED,
      code_verifier: REDACTED,
      codeChallenge: REDACTED,
      Authorization: REDACTED,
      "set-cookie": REDACTED,
      apiKey: REDACTED,
      artifact: REDACTED,
      ciphertextRef: REDACTED,
      signature: REDACTED,
      privateKey: REDACTED,
      requestId: "request-1",
    });
  });

  it("keeps a machine error code readable", () => {
    expect(redactForLog({ errorCode: "relay_expired", status: 410 })).toEqual({
      errorCode: "relay_expired",
      status: 410,
    });
  });

  it("redacts every URL-shaped key", () => {
    expect(
      redactForLog({ redirectUri: "https://app.example/cb?code=abc", providerUrl: "bad" }),
    ).toEqual({
      redirectUri: "https://app.example/cb",
      providerUrl: "[unreadable-url]",
    });
  });

  it("never repeats a provider or driver message", () => {
    expect(redactForLog(new TypeError("connect ECONNREFUSED user:password@host"))).toEqual({
      name: "TypeError",
      message: REDACTED,
    });
  });

  it("bounds depth, breadth, and length", () => {
    expect(redactForLog({ a: { b: { c: { d: 1 } } } })).toEqual({ a: { b: { c: REDACTED } } });
    expect(redactForLog(Array.from({ length: 20 }, (_, index) => index))).toEqual([
      ...Array.from({ length: 16 }, (_, index) => index),
      "[truncated]",
    ]);
    expect(redactForLog(Array.from({ length: 16 }, () => 1))).toHaveLength(16);

    const wide = Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`k${index}`, index]));
    const redacted = redactForLog(wide) as Record<string, unknown>;
    expect(Object.keys(redacted)).toHaveLength(17);
    expect(redacted["[truncated]"]).toBe(true);

    expect(redactForLog("x".repeat(200))).toBe(`${"x".repeat(128)}[truncated]`);
  });

  it("passes through only finite scalars", () => {
    expect(redactForLog(null)).toBeNull();
    expect(redactForLog(true)).toBe(true);
    expect(redactForLog(7)).toBe(7);
    expect(redactForLog(Number.NaN)).toBe("NaN");
    expect(redactForLog(Number.POSITIVE_INFINITY)).toBe("Infinity");
    expect(redactForLog(10n)).toBe("10");
    expect(redactForLog(undefined)).toBe(REDACTED);
    expect(redactForLog(Symbol("s"))).toBe(REDACTED);
    expect(redactForLog(() => 1)).toBe(REDACTED);
  });
});
