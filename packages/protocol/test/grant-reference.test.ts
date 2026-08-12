import { describe, expect, it } from "vitest";
import {
  type GrantPolicy,
  hashGrantPolicyCalls,
  OAATH_GRANT_REFERENCE_APPROVED_REVISION,
  OAATH_GRANT_REFERENCE_VERSION,
  OaathGrantPolicyError,
  type OaathGrantRef,
  OaathProtocolError,
  parseGrantVerificationResult,
  parseOaathGrantRef,
  parseVerifyGrantRevisionInput,
} from "../src/index.js";

const firstTarget = `0x${"11".repeat(20)}` as const;
const secondTarget = `0x${"22".repeat(20)}` as const;
const digest = `0x${"ab".repeat(32)}` as const;

const calls: GrantPolicy["calls"] = [
  {
    target: firstTarget,
    selector: "0x12345678",
    valueLimit: "100",
    argumentEquals: [{ index: 0, value: `0x${"33".repeat(32)}` }],
  },
  {
    target: secondTarget,
    selector: "0xabcdef01",
    valueLimit: "0",
    argumentEquals: [],
  },
];

const ref: OaathGrantRef = {
  version: OAATH_GRANT_REFERENCE_VERSION,
  grantId: "grant-abc",
  revision: OAATH_GRANT_REFERENCE_APPROVED_REVISION,
  subject: "subject-1",
  clientId: "client-a",
  organizationAudience: "org-1",
  state: "active",
  policyDigest: digest,
};

const input = {
  grantId: "grant-abc",
  revision: 1,
  subject: "subject-1",
  clientId: "client-a",
  organizationAudience: "org-1",
  requiredCallsDigest: digest,
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

describe("hashGrantPolicyCalls", () => {
  it("is deterministic over an exact canonical call set", () => {
    expect(hashGrantPolicyCalls(clone(calls))).toBe(hashGrantPolicyCalls(clone(calls)));
    expect(hashGrantPolicyCalls(clone(calls))).toMatch(/^0x[0-9a-f]{64}$/u);
  });

  it("changes when any call fact changes", () => {
    const whole = hashGrantPolicyCalls(clone(calls));
    const narrower = clone(calls).slice(0, 1);
    expect(hashGrantPolicyCalls(narrower)).not.toBe(whole);
    const differentValue = clone(calls).map((call, index) =>
      index === 0 ? { ...call, valueLimit: "101" } : call,
    );
    expect(hashGrantPolicyCalls(differentValue)).not.toBe(whole);
  });

  it("rejects an empty, unsorted, or duplicated call set", () => {
    expect(() => hashGrantPolicyCalls([])).toThrow(OaathGrantPolicyError);
    expect(() => hashGrantPolicyCalls([...clone(calls)].reverse())).toThrow(OaathGrantPolicyError);
    const duplicated = clone(calls);
    expect(() => hashGrantPolicyCalls([duplicated[0], duplicated[0]])).toThrow(
      OaathGrantPolicyError,
    );
  });
});

describe("parseVerifyGrantRevisionInput", () => {
  it("captures an exact input", () => {
    expect(parseVerifyGrantRevisionInput(clone(input))).toEqual(input);
  });

  it("rejects unknown fields, bad revisions, and malformed digests", () => {
    expect(() => parseVerifyGrantRevisionInput({ ...clone(input), extra: 1 })).toThrow(
      OaathProtocolError,
    );
    expect(() => parseVerifyGrantRevisionInput({ ...clone(input), revision: 0 })).toThrow(
      OaathProtocolError,
    );
    expect(() => parseVerifyGrantRevisionInput({ ...clone(input), revision: 1.5 })).toThrow(
      OaathProtocolError,
    );
    expect(() =>
      parseVerifyGrantRevisionInput({ ...clone(input), requiredCallsDigest: "0x00" }),
    ).toThrow(OaathProtocolError);
    expect(() =>
      parseVerifyGrantRevisionInput({ ...clone(input), organizationAudience: "bad audience" }),
    ).toThrow(OaathProtocolError);
  });
});

describe("parseGrantVerificationResult", () => {
  it("parses the three result states exactly", () => {
    expect(parseGrantVerificationResult({ state: "authorized", ref: clone(ref) })).toEqual({
      state: "authorized",
      ref,
    });
    expect(parseGrantVerificationResult({ state: "denied", code: "grant_revoked" })).toEqual({
      state: "denied",
      code: "grant_revoked",
    });
    expect(parseGrantVerificationResult({ state: "unknown", code: "grant_unreadable" })).toEqual({
      state: "unknown",
      code: "grant_unreadable",
    });
  });

  it("never authorizes an unreadable result", () => {
    expect(() => parseGrantVerificationResult({ state: "authorized" })).toThrow(OaathProtocolError);
    expect(() =>
      parseGrantVerificationResult({ state: "authorized", ref: { ...clone(ref), state: "odd" } }),
    ).toThrow(OaathProtocolError);
    expect(() => parseGrantVerificationResult({ state: "denied", code: "not_a_code" })).toThrow(
      OaathProtocolError,
    );
    expect(() => parseGrantVerificationResult({ state: "unknown", code: "grant_revoked" })).toThrow(
      OaathProtocolError,
    );
    expect(() => parseGrantVerificationResult({ state: "granted" })).toThrow(OaathProtocolError);
  });
});

describe("parseOaathGrantRef", () => {
  it("round-trips the immutable evidence", () => {
    const parsed = parseOaathGrantRef(clone(ref));
    expect(parsed).toEqual(ref);
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it("rejects a wrong version or missing binding", () => {
    expect(() =>
      parseOaathGrantRef({ ...clone(ref), version: "oaath.grant-reference/v0" }),
    ).toThrow(OaathProtocolError);
    const { organizationAudience: _omitted, ...withoutAudience } = clone(ref);
    expect(() => parseOaathGrantRef(withoutAudience)).toThrow(OaathProtocolError);
  });
});
