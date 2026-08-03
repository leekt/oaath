import { describe, expect, it } from "vitest";
import {
  durationBetween,
  MAX_PROTOCOL_TIMESTAMP,
  OaathProtocolError,
  parseDuration,
  parseTimestamp,
} from "../src/index.js";

function expectTimeError(action: () => unknown): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code: "protocol_time_invalid" });
    return;
  }
  throw new Error("Expected protocol_time_invalid");
}

describe("canonical protocol time", () => {
  it("accepts only whole bounded seconds", () => {
    expect(MAX_PROTOCOL_TIMESTAMP).toBe(2 ** 48 - 1);
    for (const parse of [parseTimestamp, parseDuration]) {
      expect(parse(0)).toBe(0);
      expect(parse(1_700_000_000)).toBe(1_700_000_000);
      expect(parse(MAX_PROTOCOL_TIMESTAMP)).toBe(MAX_PROTOCOL_TIMESTAMP);
      for (const value of [
        -1,
        -0,
        1.5,
        Number.NaN,
        Number.POSITIVE_INFINITY,
        MAX_PROTOCOL_TIMESTAMP + 1,
        "1700000000",
        1n,
        null,
        undefined,
        new Date(0),
      ]) {
        expectTimeError(() => parse(value));
      }
    }
  });

  it("measures a forward-only duration between two timestamps", () => {
    const earlier = parseTimestamp(1_000);
    const later = parseTimestamp(1_600);
    expect(durationBetween(earlier, later)).toBe(600);
    expect(durationBetween(earlier, earlier)).toBe(0);
    expectTimeError(() => durationBetween(later, earlier));
  });

  it("routes failures to a caller-supplied owner code when one is given", () => {
    const fail = (message: string): never => {
      throw new RangeError(message);
    };
    expect(() => parseTimestamp(-1, "issuedAt", fail)).toThrow(RangeError);
    expect(() => parseDuration(1.5, "lifetime", fail)).toThrow(RangeError);
    expect(() => durationBetween(parseTimestamp(2), parseTimestamp(1), "lifetime", fail)).toThrow(
      RangeError,
    );
  });
});
