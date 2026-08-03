import { describe, expect, it, vi } from "vitest";
import {
  createSubjectBinding,
  hashPermissionRequest,
  isOaathProtocolErrorCode,
  OAATH_BROWSER_ENVELOPE_VERSION,
  OAATH_PROTOCOL_ERROR_CODES,
  OaathProtocolError,
  parseBrowserEnvelope,
  protocolErrorStatus,
  serverErrorEnvelope,
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

const requestEnvelope = {
  version: OAATH_BROWSER_ENVELOPE_VERSION,
  kind: "authorization_request",
  payload: {
    version: "oaath.authorization-request/v1",
    issuer,
    client,
    subject,
    permission,
  },
};

const decisionEnvelope = {
  version: OAATH_BROWSER_ENVELOPE_VERSION,
  kind: "authorization_decision",
  payload: {
    version: "oaath.authorization-decision/v1",
    subjectId: subject.subjectId,
    decision: {
      version: "oaath.permission-decision/v1",
      kind: "reject",
      requestId: permission.requestId,
      requestHash: hashPermissionRequest(permission),
      decidedAt: 120,
    },
  },
};

/** Statuses are policy: state already decided elsewhere cannot be retried. */
const CONFLICT_CODES = [
  "authorization_code_transition_forbidden",
  "grant_identity_mismatch",
  "grant_transition_forbidden",
  "operation_identity_mismatch",
  "operation_transition_forbidden",
  "permission_request_binding_mismatch",
  "permission_decision_binding_mismatch",
  "permission_decision_conflict",
  "permission_decision_stale",
  "permission_policy_widening",
];

const INTERNAL_CODES = ["grant_revision_exhausted", "operation_revision_exhausted"];

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectEnvelopeError(action: () => unknown): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code: "wire_envelope_invalid" });
    return;
  }
  throw new Error("Expected wire_envelope_invalid");
}

describe("browser envelope", () => {
  it("carries exactly one closed kind per message", () => {
    expect(OAATH_BROWSER_ENVELOPE_VERSION).toBe("oaath.browser-envelope/v1");
    for (const envelope of [requestEnvelope, decisionEnvelope]) {
      const parsed = parseBrowserEnvelope(clone(envelope));
      expect(parsed).toEqual(envelope);
      expect(Object.isFrozen(parsed)).toBe(true);
      expect(Object.isFrozen(parsed.payload)).toBe(true);
    }
  });

  it("accepts an error payload of one protocol code and nothing else", () => {
    const envelope = serverErrorEnvelope("permission_decision_conflict");
    expect(envelope).toEqual({
      version: OAATH_BROWSER_ENVELOPE_VERSION,
      kind: "error",
      payload: { code: "permission_decision_conflict" },
    });
    expect(Object.isFrozen(envelope)).toBe(true);
    expect(Object.isFrozen(envelope.payload)).toBe(true);
    expect(parseBrowserEnvelope(clone(envelope))).toEqual(envelope);

    for (const payload of [
      { code: "not_a_protocol_code" },
      { code: 7 },
      { code: "permission_decision_conflict", message: "leaked prose" },
      {},
      "permission_decision_conflict",
      null,
    ]) {
      expectEnvelopeError(() =>
        parseBrowserEnvelope({ version: OAATH_BROWSER_ENVELOPE_VERSION, kind: "error", payload }),
      );
    }
  });

  it("rejects versions, unknown kinds, extras, and hostile accessors", () => {
    for (const value of [
      { ...requestEnvelope, version: "oaath.browser-envelope/v0" },
      { ...requestEnvelope, kind: "authorization_probe" },
      { ...requestEnvelope, extra: true },
      { version: OAATH_BROWSER_ENVELOPE_VERSION, kind: "error" },
      [requestEnvelope],
      null,
      "authorization_request",
    ]) {
      expectEnvelopeError(() => parseBrowserEnvelope(value));
    }

    expectEnvelopeError(() =>
      parseBrowserEnvelope({
        ...requestEnvelope,
        payload: { ...requestEnvelope.payload, client: { ...client, clientId: "other-client" } },
      }),
    );

    const getter = vi.fn(() => "error");
    const accessor = { ...serverErrorEnvelope("grant_input_invalid") } as Record<string, unknown>;
    Object.defineProperty(accessor, "kind", { enumerable: true, get: getter });
    expectEnvelopeError(() => parseBrowserEnvelope(accessor));
    expect(getter).not.toHaveBeenCalled();
  });
});

describe("server status mapping", () => {
  it("classifies every protocol code by code alone", () => {
    expect(OAATH_PROTOCOL_ERROR_CODES.length).toBe(new Set(OAATH_PROTOCOL_ERROR_CODES).size);
    expect(Object.isFrozen(OAATH_PROTOCOL_ERROR_CODES)).toBe(true);
    for (const code of OAATH_PROTOCOL_ERROR_CODES) {
      const expected = INTERNAL_CODES.includes(code)
        ? 500
        : CONFLICT_CODES.includes(code)
          ? 409
          : 400;
      expect(protocolErrorStatus(code), code).toBe(expected);
    }
    const known: readonly string[] = OAATH_PROTOCOL_ERROR_CODES;
    for (const code of [...CONFLICT_CODES, ...INTERNAL_CODES]) {
      expect(known.includes(code), code).toBe(true);
    }
  });

  it("recognizes only the closed code set", () => {
    for (const code of OAATH_PROTOCOL_ERROR_CODES) {
      expect(isOaathProtocolErrorCode(code)).toBe(true);
    }
    for (const value of [
      "not_a_protocol_code",
      "toString",
      "constructor",
      "__proto__",
      "",
      7,
      null,
      undefined,
      Symbol("grant_input_invalid"),
    ]) {
      expect(isOaathProtocolErrorCode(value)).toBe(false);
    }
  });
});
