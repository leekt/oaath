import { describe, expect, it } from "vitest";
import {
  OaathProtocolError,
  parseAccountId,
  parseClientId,
  parseDeviceId,
  parseSubjectId,
} from "../src/index.js";

const hash = `0x${"ab".repeat(32)}`;

function expectIdError(action: () => unknown): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code: "protocol_id_invalid" });
    return;
  }
  throw new Error("Expected protocol_id_invalid");
}

describe("canonical protocol ids", () => {
  it("accepts one bounded lowercase shape for client, device, and account ids", () => {
    for (const parse of [parseClientId, parseDeviceId, parseAccountId]) {
      expect(parse("oaath-browser.1_x")).toBe("oaath-browser.1_x");
      expect(parse("a".repeat(64))).toBe("a".repeat(64));
      for (const value of [
        "",
        "A",
        "-leading",
        ".leading",
        "space id",
        "a".repeat(65),
        " padded",
        "tab\t",
        "id\0",
        123,
        null,
        undefined,
        Object("string"),
      ]) {
        expectIdError(() => parse(value));
      }
    }
  });

  it("requires derived 32-byte hashes for subject ids", () => {
    for (const parse of [parseSubjectId]) {
      expect(parse(hash)).toBe(hash);
      for (const value of [
        hash.toUpperCase(),
        hash.slice(0, -1),
        `${hash}0`,
        hash.slice(2),
        "0x",
        null,
      ]) {
        expectIdError(() => parse(value));
      }
    }
  });

  it("routes failures to a caller-supplied owner code when one is given", () => {
    const fail = (message: string): never => {
      throw new RangeError(message);
    };
    expect(() => parseClientId("BAD", fail)).toThrow(RangeError);
    expect(() => parseSubjectId("0x", fail)).toThrow(RangeError);
  });
});
