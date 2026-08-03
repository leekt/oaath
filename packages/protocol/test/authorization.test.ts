import { describe, expect, it, vi } from "vitest";
import {
  advanceAuthorizationCode,
  createSubjectBinding,
  deriveCodeChallenge,
  hashAuthorizationCode,
  hashPermissionRequest,
  MAX_AUTHORIZATION_CODE_LIFETIME,
  OAATH_AUTHORIZATION_CODE_VERSION,
  OAATH_AUTHORIZATION_DECISION_VERSION,
  OAATH_AUTHORIZATION_REQUEST_VERSION,
  OaathPermissionProtocolError,
  OaathProtocolError,
  parseAuthorizationCode,
  parseAuthorizationDecision,
  parseAuthorizationRequest,
} from "../src/index.js";

const issuer = { version: "oaath.issuer/v1", url: "https://issuer.example.com" } as const;

const client = {
  version: "oaath.client-binding/v1",
  clientId: "oaath-browser",
  origin: "https://app.example.com",
  redirectUris: ["https://app.example.com/callback"],
  applicationName: "OAAth Example App",
};

const subject = createSubjectBinding({
  issuer: issuer.url,
  clientId: client.clientId,
  userHandle: "user-handle-7",
  deviceId: "device-1",
});

const permission = {
  version: "oaath.permission-request/v1",
  requestId: "authorization-request-1",
  application: {
    applicationId: "oaath-example",
    clientId: client.clientId,
    origin: client.origin,
    deviceId: "device-1",
  },
  chainScope: "all",
  logicalAccount: {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "7",
    kernelVersion: "0.4.0",
    factoryRoute: "meta_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"33".repeat(20)}`,
    },
  },
  operatorCredential: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"44".repeat(20)}`,
  },
  policy: {
    version: "oaath.grant-policy/v1",
    calls: [
      {
        target: `0x${"11".repeat(20)}`,
        selector: "0x12345678",
        valueLimit: "100",
        argumentEquals: [],
      },
    ],
    validAfter: 100,
    validUntil: 190,
    perChainOperationLimit: 10,
  },
  requestedAt: 100,
  expiresAt: 200,
};

const authorizationRequest = {
  version: OAATH_AUTHORIZATION_REQUEST_VERSION,
  issuer,
  client,
  subject,
  permission,
};

const decision = {
  version: "oaath.permission-decision/v1",
  kind: "approve",
  requestId: permission.requestId,
  requestHash: hashPermissionRequest(permission),
  decidedAt: 120,
  approvedPolicy: permission.policy,
  capabilityHash: `0x${"55".repeat(32)}`,
};

const authorizationDecision = {
  version: OAATH_AUTHORIZATION_DECISION_VERSION,
  subjectId: subject.subjectId,
  decision,
};

const code = "authorization-code-token-1234567890";
const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const issuedCode = {
  version: OAATH_AUTHORIZATION_CODE_VERSION,
  state: "issued",
  codeHash: hashAuthorizationCode(code),
  codeChallenge,
  codeChallengeMethod: "S256",
  clientId: client.clientId,
  subjectId: subject.subjectId,
  requestId: permission.requestId,
  issuedAt: 1_000,
  expiresAt: 1_120,
  consumedAt: null,
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectProtocolError(action: () => unknown, code: OaathProtocolError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code });
    return;
  }
  throw new Error(`Expected ${code}`);
}

describe("authorization request envelope", () => {
  it("wraps the owned permission request and freezes the actors", () => {
    const parsed = parseAuthorizationRequest(clone(authorizationRequest));
    expect(parsed).toEqual(authorizationRequest);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.client)).toBe(true);
    expect(Object.isFrozen(parsed.permission)).toBe(true);
    // The permission request codec stays the one owner of its own hash.
    expect(hashPermissionRequest(parsed.permission)).toBe(hashPermissionRequest(permission));
  });

  it("rejects actors that disagree with the permission request binding", () => {
    for (const value of [
      {
        ...authorizationRequest,
        issuer: { ...issuer, url: "https://other-issuer.example.com" },
      },
      {
        ...authorizationRequest,
        client: { ...client, clientId: "other-client" },
      },
      {
        ...authorizationRequest,
        subject: createSubjectBinding({
          issuer: issuer.url,
          clientId: client.clientId,
          userHandle: "user-handle-7",
          deviceId: "device-2",
        }),
      },
      {
        ...authorizationRequest,
        permission: {
          ...permission,
          application: { ...permission.application, clientId: "other-client" },
        },
      },
      {
        ...authorizationRequest,
        permission: {
          ...permission,
          application: { ...permission.application, origin: "https://other.example.com" },
        },
      },
      {
        ...authorizationRequest,
        permission: {
          ...permission,
          application: { ...permission.application, deviceId: "device-9" },
        },
      },
      { ...authorizationRequest, version: "oaath.authorization-request/v0" },
      { ...authorizationRequest, extra: true },
      null,
    ]) {
      expectProtocolError(() => parseAuthorizationRequest(value), "authorization_request_invalid");
    }
  });

  it("rejects aliased actors and hostile accessors without reading them", () => {
    const shared = { ...client };
    expectProtocolError(
      () => parseAuthorizationRequest({ ...authorizationRequest, client: shared, subject: shared }),
      "authorization_request_invalid",
    );

    const getter = vi.fn(() => issuer);
    const accessor = { ...authorizationRequest } as Record<string, unknown>;
    Object.defineProperty(accessor, "issuer", { enumerable: true, get: getter });
    expectProtocolError(() => parseAuthorizationRequest(accessor), "authorization_request_invalid");
    expect(getter).not.toHaveBeenCalled();
  });

  it("keeps the permission request codec's own error code when the payload is bad", () => {
    try {
      parseAuthorizationRequest({
        ...authorizationRequest,
        permission: { ...permission, expiresAt: 50 },
      });
      throw new Error("Expected permission_request_invalid");
    } catch (error) {
      expect(error).toBeInstanceOf(OaathPermissionProtocolError);
      expect(error).toMatchObject({ code: "permission_request_invalid" });
    }
  });
});

describe("authorization decision envelope", () => {
  it("binds one terminal decision to one pairwise subject", () => {
    const parsed = parseAuthorizationDecision(clone(authorizationDecision));
    expect(parsed).toEqual(authorizationDecision);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(
      parseAuthorizationDecision({
        ...authorizationDecision,
        decision: {
          version: "oaath.permission-decision/v1",
          kind: "reject",
          requestId: permission.requestId,
          requestHash: decision.requestHash,
          decidedAt: 120,
        },
      }).decision.kind,
    ).toBe("reject");
  });

  it("rejects foreign subjects, versions, and extras", () => {
    for (const value of [
      { ...authorizationDecision, subjectId: "not-a-hash" },
      { ...authorizationDecision, version: "oaath.authorization-decision/v0" },
      { ...authorizationDecision, extra: true },
      { version: OAATH_AUTHORIZATION_DECISION_VERSION, decision },
      null,
    ]) {
      expectProtocolError(
        () => parseAuthorizationDecision(value),
        "authorization_decision_invalid",
      );
    }
    try {
      parseAuthorizationDecision({
        ...authorizationDecision,
        decision: { ...decision, kind: "maybe" },
      });
      throw new Error("Expected permission_decision_invalid");
    } catch (error) {
      expect(error).toBeInstanceOf(OaathPermissionProtocolError);
      expect(error).toMatchObject({ code: "permission_decision_invalid" });
    }
  });
});

describe("authorization code and PKCE challenge", () => {
  it("derives the RFC 7636 S256 challenge and the stored code digest", () => {
    expect(MAX_AUTHORIZATION_CODE_LIFETIME).toBe(600);
    expect(deriveCodeChallenge(codeVerifier)).toBe(codeChallenge);
    expect(hashAuthorizationCode(code)).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(hashAuthorizationCode(code)).toBe(hashAuthorizationCode(code));
    expect(hashAuthorizationCode(`${code}x`)).not.toBe(hashAuthorizationCode(code));
    for (const value of ["short", `${code}!`, "a".repeat(129), 7, null]) {
      expectProtocolError(() => hashAuthorizationCode(value), "authorization_code_invalid");
    }
    for (const value of ["a".repeat(42), "a".repeat(129), `${codeVerifier}!`, 7, null]) {
      expectProtocolError(() => deriveCodeChallenge(value), "authorization_code_verifier_mismatch");
    }
  });

  it("captures the three code states immutably", () => {
    const parsed = parseAuthorizationCode(clone(issuedCode));
    expect(parsed).toEqual(issuedCode);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(parseAuthorizationCode({ ...issuedCode, state: "expired" }).state).toBe("expired");
    expect(
      parseAuthorizationCode({ ...issuedCode, state: "consumed", consumedAt: 1_010 }),
    ).toMatchObject({ state: "consumed", consumedAt: 1_010 });
  });

  it("rejects unsupported, contradictory, and unbounded code records", () => {
    for (const value of [
      { ...issuedCode, version: "oaath.authorization-code/v0" },
      { ...issuedCode, state: "revoked" },
      { ...issuedCode, codeChallengeMethod: "plain" },
      { ...issuedCode, codeChallenge: `${codeChallenge}=` },
      { ...issuedCode, codeChallenge: 7 },
      { ...issuedCode, codeHash: issuedCode.codeHash.toUpperCase() },
      { ...issuedCode, codeHash: null },
      { ...issuedCode, clientId: "Not-Lower" },
      { ...issuedCode, subjectId: "0x00" },
      { ...issuedCode, requestId: " untrimmed " },
      { ...issuedCode, issuedAt: -1 },
      { ...issuedCode, expiresAt: 1.5 },
      { ...issuedCode, expiresAt: issuedCode.issuedAt },
      { ...issuedCode, expiresAt: issuedCode.issuedAt + 601 },
      { ...issuedCode, consumedAt: 1_010 },
      { ...issuedCode, state: "expired", consumedAt: 1_010 },
      { ...issuedCode, state: "consumed", consumedAt: null },
      { ...issuedCode, state: "consumed", consumedAt: 999 },
      { ...issuedCode, state: "consumed", consumedAt: 1_120 },
      { ...issuedCode, extra: true },
      null,
    ]) {
      expectProtocolError(() => parseAuthorizationCode(value), "authorization_code_invalid");
    }
  });

  it("consumes an issued code exactly once with the matching verifier", () => {
    const consumed = advanceAuthorizationCode(clone(issuedCode), {
      type: "consume",
      code,
      codeVerifier,
      consumedAt: 1_010,
    });
    expect(consumed).toEqual({ ...issuedCode, state: "consumed", consumedAt: 1_010 });
    expect(Object.isFrozen(consumed)).toBe(true);

    expectProtocolError(
      () =>
        advanceAuthorizationCode(consumed, {
          type: "consume",
          code,
          codeVerifier,
          consumedAt: 1_011,
        }),
      "authorization_code_transition_forbidden",
    );
    expectProtocolError(
      () => advanceAuthorizationCode(consumed, { type: "expire", expiredAt: 1_120 }),
      "authorization_code_transition_forbidden",
    );
  });

  it("refuses a wrong code, a wrong verifier, and an out-of-window redemption", () => {
    expectProtocolError(
      () =>
        advanceAuthorizationCode(issuedCode, {
          type: "consume",
          code: `${code}9`,
          codeVerifier,
          consumedAt: 1_010,
        }),
      "authorization_code_invalid",
    );
    expectProtocolError(
      () =>
        advanceAuthorizationCode(issuedCode, {
          type: "consume",
          code,
          codeVerifier: codeVerifier.replace("dBj", "dBk"),
          consumedAt: 1_010,
        }),
      "authorization_code_verifier_mismatch",
    );
    expectProtocolError(
      () =>
        advanceAuthorizationCode(issuedCode, {
          type: "consume",
          code,
          codeVerifier: "short",
          consumedAt: 1_010,
        }),
      "authorization_code_verifier_mismatch",
    );
    for (const consumedAt of [999, 1_120, 2_000]) {
      expectProtocolError(
        () =>
          advanceAuthorizationCode(issuedCode, { type: "consume", code, codeVerifier, consumedAt }),
        "authorization_code_transition_forbidden",
      );
    }
  });

  it("expires only at or after expiresAt and only from issued", () => {
    const expired = advanceAuthorizationCode(issuedCode, { type: "expire", expiredAt: 1_120 });
    expect(expired).toEqual({ ...issuedCode, state: "expired", consumedAt: null });
    expectProtocolError(
      () => advanceAuthorizationCode(issuedCode, { type: "expire", expiredAt: 1_119 }),
      "authorization_code_transition_forbidden",
    );
    expectProtocolError(
      () => advanceAuthorizationCode(expired, { type: "expire", expiredAt: 1_200 }),
      "authorization_code_transition_forbidden",
    );
  });

  it("captures the transition itself exactly", () => {
    for (const transition of [
      { type: "consume", code, codeVerifier },
      { type: "consume", code, codeVerifier, consumedAt: 1_010, extra: true },
      { type: "consume", code: 7, codeVerifier, consumedAt: 1_010 },
      { type: "consume", code, codeVerifier: 7, consumedAt: 1_010 },
      { type: "consume", code, codeVerifier, consumedAt: "1010" },
      { type: "expire" },
      { type: "expire", expiredAt: -1 },
      { type: "resume", expiredAt: 1_120 },
      null,
      [{ type: "expire", expiredAt: 1_120 }],
    ]) {
      expectProtocolError(
        () => advanceAuthorizationCode(issuedCode, transition),
        "authorization_code_invalid",
      );
    }

    const getter = vi.fn(() => "expire");
    const accessor = { expiredAt: 1_120 } as Record<string, unknown>;
    Object.defineProperty(accessor, "type", { enumerable: true, get: getter });
    expectProtocolError(
      () => advanceAuthorizationCode(issuedCode, accessor),
      "authorization_code_invalid",
    );
    expect(getter).not.toHaveBeenCalled();
  });
});
