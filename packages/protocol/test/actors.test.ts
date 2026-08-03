import { describe, expect, it, vi } from "vitest";
import {
  createSubjectBinding,
  deriveSubjectId,
  type IssuerIdentity,
  OAATH_CLIENT_BINDING_VERSION,
  OAATH_ISSUER_VERSION,
  OAATH_SUBJECT_HASH_DOMAIN,
  OAATH_SUBJECT_VERSION,
  OaathProtocolError,
  parseClientBinding,
  parseIssuerIdentity,
  parseSubjectBinding,
} from "../src/index.js";

const issuer: IssuerIdentity = {
  version: "oaath.issuer/v1",
  url: "https://issuer.example.com",
};

const client = {
  version: "oaath.client-binding/v1",
  clientId: "oaath-browser",
  origin: "https://app.example.com",
  redirectUris: ["https://app.example.com/callback", "https://app.example.com"],
  applicationName: "OAAth Example App",
};

const subjectInput = {
  issuer: issuer.url,
  clientId: "oaath-browser",
  userHandle: "user-handle-7",
  deviceId: "device-1",
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectActorError(action: () => unknown, code: OaathProtocolError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code });
    return;
  }
  throw new Error(`Expected ${code}`);
}

describe("issuer identity", () => {
  it("accepts one canonical https form and freezes it", () => {
    expect(OAATH_ISSUER_VERSION).toBe("oaath.issuer/v1");
    const parsed = parseIssuerIdentity(clone(issuer));
    expect(parsed).toEqual(issuer);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(parseIssuerIdentity({ ...issuer, url: "https://issuer.example.com/tenant/a" })).toEqual({
      ...issuer,
      url: "https://issuer.example.com/tenant/a",
    });
  });

  it("rejects every non-canonical URL instead of rewriting it", () => {
    for (const url of [
      "https://issuer.example.com/",
      "https://issuer.example.com/tenant/",
      "https://Issuer.example.com",
      "https://issuer.example.com:443",
      "https://issuer.example.com?a=1",
      "https://issuer.example.com#a",
      "https://user:pass@issuer.example.com",
      "http://issuer.example.com",
      "wss://issuer.example.com",
      "issuer.example.com",
      "",
      `https://issuer.example.com/${"a".repeat(2_048)}`,
      42,
      null,
    ]) {
      expectActorError(() => parseIssuerIdentity({ ...issuer, url }), "issuer_invalid");
    }
    for (const value of [
      { version: "oaath.issuer/v0", url: issuer.url },
      { url: issuer.url },
      { ...issuer, extra: true },
      [issuer],
      null,
      "https://issuer.example.com",
    ]) {
      expectActorError(() => parseIssuerIdentity(value), "issuer_invalid");
    }
  });
});

describe("client binding", () => {
  it("captures the exact redirect list immutably", () => {
    expect(OAATH_CLIENT_BINDING_VERSION).toBe("oaath.client-binding/v1");
    const mutable = clone(client) as unknown as Record<string, unknown>;
    const parsed = parseClientBinding(mutable);
    mutable.clientId = "changed";
    (mutable.redirectUris as string[]).push("https://app.example.com/injected");
    expect(parsed).toEqual(client);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.redirectUris)).toBe(true);
    expect(parsed.redirectUris).toEqual([
      "https://app.example.com/callback",
      "https://app.example.com",
    ]);
  });

  it("requires an origin with no path and exact same-origin redirect targets", () => {
    expectActorError(
      () => parseClientBinding({ ...client, origin: "https://app.example.com/base" }),
      "client_binding_invalid",
    );
    for (const redirectUris of [
      [],
      ["https://other.example.com/callback"],
      ["https://app.example.com.evil.com/callback"],
      ["https://app.example.com/callback", "https://app.example.com/callback"],
      ["https://app.example.com/callback/"],
      ["http://app.example.com/callback"],
      Array.from({ length: 9 }, (_, index) => `https://app.example.com/cb${index}`),
      "https://app.example.com/callback",
      [null],
    ]) {
      expectActorError(
        () => parseClientBinding({ ...client, redirectUris }),
        "client_binding_invalid",
      );
    }
  });

  it("rejects versions, names, ids, extras, accessors, and aliasing", () => {
    for (const value of [
      { ...client, version: "oaath.client-binding/v0" },
      { ...client, clientId: "Not-Lower" },
      { ...client, applicationName: "" },
      { ...client, applicationName: " leading space" },
      { ...client, applicationName: "double  space" },
      { ...client, applicationName: "line\nbreak" },
      { ...client, applicationName: "a".repeat(65) },
      { ...client, applicationName: 7 },
      { ...client, extra: true },
      { version: client.version, clientId: client.clientId },
    ]) {
      expectActorError(() => parseClientBinding(value), "client_binding_invalid");
    }

    const getter = vi.fn(() => "oaath-browser");
    const accessor = { ...client } as Record<string, unknown>;
    Object.defineProperty(accessor, "clientId", { enumerable: true, get: getter });
    expectActorError(() => parseClientBinding(accessor), "client_binding_invalid");
    expect(getter).not.toHaveBeenCalled();

    const prototyped = Object.create({ inherited: true }) as Record<string, unknown>;
    Object.assign(prototyped, client);
    expectActorError(() => parseClientBinding(prototyped), "client_binding_invalid");
  });

  it("sanitizes hostile reflection failures", () => {
    const secret = "do-not-leak-client-secret";
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error(secret);
        },
      },
    );
    try {
      parseClientBinding(hostile);
      throw new Error("Expected client_binding_invalid");
    } catch (error) {
      expect(error).toBeInstanceOf(OaathProtocolError);
      expect(error).toMatchObject({ code: "client_binding_invalid" });
      expect((error as Error).message).not.toContain(secret);
    }
  });
});

describe("pairwise subject binding", () => {
  it("derives one subjectId per issuer, client, user, and device tuple", () => {
    expect(OAATH_SUBJECT_VERSION).toBe("oaath.subject/v1");
    expect(OAATH_SUBJECT_HASH_DOMAIN).toBe("@oaath/protocol:subject");
    const binding = createSubjectBinding(clone(subjectInput));
    expect(binding).toEqual({
      version: OAATH_SUBJECT_VERSION,
      ...subjectInput,
      subjectId: binding.subjectId,
    });
    expect(deriveSubjectId(binding)).toBe(binding.subjectId);
    expect(Object.isFrozen(binding)).toBe(true);
    expect(binding.subjectId).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(createSubjectBinding(clone(subjectInput)).subjectId).toBe(binding.subjectId);

    const pairwise = new Set([binding.subjectId]);
    for (const changed of [
      { issuer: "https://other-issuer.example.com" },
      { clientId: "other-client" },
      { userHandle: "user-handle-8" },
      { deviceId: "device-2" },
    ]) {
      pairwise.add(createSubjectBinding({ ...subjectInput, ...changed }).subjectId);
    }
    expect(pairwise.size).toBe(5);
  });

  it("never lets a supplied subjectId stand in for the derivation", () => {
    const binding = createSubjectBinding(subjectInput);
    expect(parseSubjectBinding(clone(binding))).toEqual(binding);
    expectActorError(
      () => parseSubjectBinding({ ...binding, subjectId: `0x${"11".repeat(32)}` }),
      "subject_binding_invalid",
    );
    expectActorError(
      () => parseSubjectBinding({ ...binding, deviceId: "device-2" }),
      "subject_binding_invalid",
    );
    expectActorError(
      () => parseSubjectBinding({ ...binding, subjectId: binding.subjectId.toUpperCase() }),
      "subject_binding_invalid",
    );
  });

  it("bounds the opaque user handle and rejects malformed inputs", () => {
    for (const userHandle of ["", " ", "with space", "a".repeat(256), "é", 7, null]) {
      expectActorError(
        () => createSubjectBinding({ ...subjectInput, userHandle }),
        "subject_binding_invalid",
      );
    }
    for (const value of [
      { ...subjectInput, issuer: "https://issuer.example.com/" },
      { ...subjectInput, clientId: "Bad" },
      { ...subjectInput, deviceId: "" },
      { ...subjectInput, extra: true },
      { issuer: subjectInput.issuer },
      null,
    ]) {
      expectActorError(() => createSubjectBinding(value), "subject_binding_invalid");
    }
    expectActorError(
      () =>
        parseSubjectBinding({
          ...subjectInput,
          version: "oaath.subject/v0",
          subjectId: `0x${"11".repeat(32)}`,
        }),
      "subject_binding_invalid",
    );
  });
});
