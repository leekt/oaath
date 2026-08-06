import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  type ApplyPermissionDecisionInput,
  type ApprovePermissionDecision,
  advanceGrant,
  applyPermissionDecision,
  createGrant,
  createGrantFromPermissionRequest,
  encodePermissionDecision,
  encodePermissionRequest,
  type GrantPolicy,
  hashGrantPolicy,
  hashPermissionDecision,
  hashPermissionRequest,
  OAATH_PERMISSION_DECISION_HASH_DOMAIN,
  OAATH_PERMISSION_DECISION_VERSION,
  OAATH_PERMISSION_REQUEST_HASH_DOMAIN,
  OAATH_PERMISSION_REQUEST_VERSION,
  OaathPermissionProtocolError,
  type PermissionDecision,
  type PermissionRequest,
  parsePermissionDecision,
  parsePermissionRequest,
  type RejectPermissionDecision,
} from "../src/index.js";

const target = `0x${"11".repeat(20)}` as const;
const argumentWord = `0x${"22".repeat(32)}` as const;
const ownerAddress = `0x${"33".repeat(20)}` as const;
const operatorAddress = `0x${"44".repeat(20)}` as const;
const capabilityHash = `0x${"55".repeat(32)}` as const;

const policy: GrantPolicy = {
  version: "oaath.grant-policy/v1",
  calls: [
    {
      target,
      selector: "0x12345678",
      valueLimit: "100",
      argumentEquals: [],
    },
  ],
  validAfter: 100,
  validUntil: 190,
  perChainOperationLimit: 10,
};

const basePolicyCall = policy.calls[0];
if (!basePolicyCall) throw new Error("missing policy call fixture");

const request: PermissionRequest = {
  version: "oaath.permission-request/v1",
  requestId: "permission-request-1",
  application: {
    applicationId: "oaath-tests",
    clientId: "permission-protocol",
    origin: "https://request.example",
    deviceId: "request-device",
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
      address: ownerAddress,
    },
  },
  operatorCredential: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: operatorAddress,
  },
  policy,
  requestedAt: 100,
  expiresAt: 200,
  sessionSigner: null,
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function approve(overrides: Partial<ApprovePermissionDecision> = {}): ApprovePermissionDecision {
  return {
    version: OAATH_PERMISSION_DECISION_VERSION,
    kind: "approve",
    requestId: request.requestId,
    requestHash: hashPermissionRequest(request),
    decidedAt: 120,
    approvedPolicy: policy,
    capabilityHash,
    ...overrides,
  };
}

function reject(overrides: Partial<RejectPermissionDecision> = {}): RejectPermissionDecision {
  return {
    version: OAATH_PERMISSION_DECISION_VERSION,
    kind: "reject",
    requestId: request.requestId,
    requestHash: hashPermissionRequest(request),
    decidedAt: 120,
    ...overrides,
  };
}

function applyInput(
  decision: PermissionDecision,
  overrides: Partial<ApplyPermissionDecisionInput> = {},
): ApplyPermissionDecisionInput {
  return {
    request,
    grant: createGrantFromPermissionRequest(request),
    observation: { status: "available", decision },
    evaluatedAt: 120,
    ...overrides,
  };
}

type RequestSubstitution =
  | "application_id"
  | "client_id"
  | "origin"
  | "device_id"
  | "logical_account"
  | "owner_credential"
  | "operator_credential"
  | "policy"
  | "request_id"
  | "requested_at"
  | "expires_at";

function substituteRequest(kind: RequestSubstitution, seed: number): PermissionRequest {
  const identifier = `changed-${seed}`;
  if (kind === "application_id") {
    return {
      ...clone(request),
      application: { ...request.application, applicationId: identifier },
    };
  }
  if (kind === "client_id") {
    return { ...clone(request), application: { ...request.application, clientId: identifier } };
  }
  if (kind === "origin") {
    return {
      ...clone(request),
      application: { ...request.application, origin: `https://${identifier}.example` },
    };
  }
  if (kind === "device_id") {
    return { ...clone(request), application: { ...request.application, deviceId: identifier } };
  }
  if (kind === "logical_account") {
    return {
      ...clone(request),
      logicalAccount: { ...request.logicalAccount, accountIndex: String(seed + 8) },
    };
  }
  const rawByte = (seed % 250) + 1;
  const substitutedByte =
    (kind === "owner_credential" && rawByte === 0x33) ||
    (kind === "operator_credential" && rawByte === 0x44)
      ? 0xfe
      : rawByte;
  const byte = substitutedByte.toString(16).padStart(2, "0");
  if (kind === "owner_credential") {
    return {
      ...clone(request),
      logicalAccount: {
        ...request.logicalAccount,
        ownerCredential: {
          version: "oaath.owner-credential-profile/v1",
          kind: "ecdsa",
          address: `0x${byte.repeat(20)}`,
        },
      },
    };
  }
  if (kind === "operator_credential") {
    return {
      ...clone(request),
      operatorCredential: {
        version: "oaath.operator-credential-profile/v1",
        kind: "ecdsa",
        address: `0x${byte.repeat(20)}`,
      },
    };
  }
  if (kind === "policy") {
    return {
      ...clone(request),
      policy: { ...clone(policy), perChainOperationLimit: seed + 11 },
    };
  }
  if (kind === "request_id") return { ...clone(request), requestId: identifier };
  if (kind === "requested_at") return { ...clone(request), requestedAt: (seed % 89) + 101 };
  return { ...clone(request), expiresAt: seed + 201 };
}

function expectProtocolError(
  action: () => unknown,
  code: OaathPermissionProtocolError["code"],
): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathPermissionProtocolError);
    expect(error).toMatchObject({ code });
    return;
  }
  throw new Error(`Expected ${code}`);
}

describe("PermissionRequest current codec", () => {
  it("captures the exact application/account/operator/policy request and creates its Grant", () => {
    expect(OAATH_PERMISSION_REQUEST_VERSION).toBe("oaath.permission-request/v1");
    expect(OAATH_PERMISSION_REQUEST_HASH_DOMAIN).toBe("@oaath/protocol:permission-request");
    const mutable = clone(request) as unknown as {
      requestId: string;
      application: { origin: string; clientId: string };
      logicalAccount: { accountIndex: string };
      policy: { calls: Array<{ valueLimit: string }> };
    };
    mutable.application.origin = "https://REQUEST.example:443/";
    const parsed = parsePermissionRequest(mutable);
    mutable.requestId = "changed";
    mutable.application.clientId = "changed";
    mutable.logicalAccount.accountIndex = "9";
    const mutableCall = mutable.policy.calls[0];
    if (!mutableCall) throw new Error("missing mutable policy call fixture");
    mutable.policy.calls[0] = { ...mutableCall, valueLimit: "999" };

    expect(parsed).toEqual(request);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.application)).toBe(true);
    expect(Object.isFrozen(parsed.logicalAccount.ownerCredential)).toBe(true);
    expect(Object.isFrozen(parsed.operatorCredential)).toBe(true);
    expect(Object.isFrozen(parsed.policy.calls)).toBe(true);
    expect(parsePermissionRequest(clone(parsed))).toEqual(parsed);

    const grant = createGrantFromPermissionRequest(parsed);
    expect(grant).toMatchObject({
      version: "oaath.grant/v3",
      state: "requested",
      revision: 0,
      requestedAt: 100,
      expiresAt: 200,
      identity: {
        grantId: request.requestId,
        chainScope: "all",
        application: request.application,
        logicalAccount: request.logicalAccount,
        operatorCredential: request.operatorCredential,
        policyHash: hashGrantPolicy(policy),
      },
      approval: null,
      materializations: [],
    });
  });

  it("uses deterministic ABI/domain-separated content hashes across recreation", () => {
    expect(encodePermissionRequest(clone(request))).toBe(encodePermissionRequest(request));
    expect(hashPermissionRequest(clone(request))).toBe(hashPermissionRequest(request));
    expect(encodePermissionRequest(request)).toMatch(/^0x[0-9a-f]+$/u);
    expect(hashPermissionRequest(request)).toBe(
      "0xcc6a47d748bd8ac5f820c460ede3fa17a12511bc2636e43efc44c105d68d0bf5",
    );
    expect(
      hashPermissionRequest({ ...clone(request), requestId: "permission-request-2" }),
    ).not.toBe(hashPermissionRequest(request));

    const mutations: PermissionRequest[] = [
      { ...clone(request), application: { ...request.application, applicationId: "other-app" } },
      { ...clone(request), application: { ...request.application, clientId: "other-client" } },
      {
        ...clone(request),
        application: { ...request.application, origin: "https://other.example" },
      },
      { ...clone(request), application: { ...request.application, deviceId: "other-device" } },
      { ...clone(request), logicalAccount: { ...request.logicalAccount, accountIndex: "8" } },
      {
        ...clone(request),
        logicalAccount: { ...request.logicalAccount, factoryRoute: "kernel_factory" },
      },
      {
        ...clone(request),
        logicalAccount: {
          ...request.logicalAccount,
          ownerCredential: {
            version: "oaath.owner-credential-profile/v1",
            kind: "ecdsa",
            address: `0x${"66".repeat(20)}`,
          },
        },
      },
      {
        ...clone(request),
        operatorCredential: {
          version: "oaath.operator-credential-profile/v1",
          kind: "ecdsa",
          address: `0x${"77".repeat(20)}`,
        },
      },
      { ...clone(request), policy: { ...clone(policy), perChainOperationLimit: 9 } },
      { ...clone(request), requestedAt: 101 },
      { ...clone(request), expiresAt: 201 },
    ];
    for (const mutation of mutations) {
      expect(hashPermissionRequest(mutation)).not.toBe(hashPermissionRequest(request));
    }
  });

  it("requires finite policy authority to end before the exclusive Grant expiry", () => {
    for (const changed of [
      { ...clone(policy), validUntil: null },
      { ...clone(policy), validUntil: 99 },
      { ...clone(policy), validUntil: 200 },
      { ...clone(policy), validUntil: 201 },
    ]) {
      expectProtocolError(
        () => parsePermissionRequest({ ...clone(request), policy: changed }),
        "permission_request_invalid",
      );
    }
    expect(
      parsePermissionRequest({ ...clone(request), policy: { ...clone(policy), validUntil: 199 } }),
    ).toMatchObject({
      policy: { validUntil: 199 },
      expiresAt: 200,
    });
  });

  it("rejects wrong versions, chain modes, times, fields, profiles, and hostile records", () => {
    const accessor = clone(request) as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "requestId", {
      enumerable: true,
      get: () => request.requestId,
    });
    const proxy = new Proxy(clone(request), {
      getOwnPropertyDescriptor() {
        throw new Error("hostile proxy");
      },
    });
    const invalidRequests: unknown[] = [
      { ...clone(request), version: "oaath.permission-request/v0" },
      { ...clone(request), chainScope: "selected" },
      { ...clone(request), chainId: 1 },
      { ...clone(request), chains: [1] },
      { ...clone(request), default: true },
      { ...clone(request), fallback: true },
      { ...clone(request), requestId: " request" },
      { ...clone(request), requestedAt: -0 },
      { ...clone(request), requestedAt: 100.5 },
      { ...clone(request), requestedAt: 2 ** 48 },
      { ...clone(request), expiresAt: 100 },
      { ...clone(request), expiresAt: 2 ** 48 },
      { ...clone(request), application: { ...request.application, extra: true } },
      { ...clone(request), logicalAccount: { ...request.logicalAccount, kernelVersion: "0.3.2" } },
      { ...clone(request), [Symbol("hidden")]: true },
      accessor,
      proxy,
    ];
    for (const value of invalidRequests) {
      expectProtocolError(() => parsePermissionRequest(value), "permission_request_invalid");
    }
  });

  it("contains no approval-time chain inventory, default, or fallback", () => {
    const keys = new Set<string>();
    const collect = (value: unknown): void => {
      if (value === null || typeof value !== "object") return;
      for (const [key, child] of Object.entries(value)) {
        keys.add(key.toLowerCase());
        collect(child);
      }
    };
    collect(parsePermissionRequest(request));
    expect(keys.has("chains")).toBe(false);
    expect(keys.has("chainid")).toBe(false);
    expect(keys.has("supportedchains")).toBe(false);
    expect(keys.has("default")).toBe(false);
    expect(keys.has("fallback")).toBe(false);
  });
});

describe("PermissionRequest session-signer custody binding", () => {
  it("keeps frontend hashes stable and binds remote custody into the request hash", () => {
    // Absent field and explicit null are both frontend custody: same parse
    // result, byte-identical encoding, so every pre-custody hash stays valid.
    const { sessionSigner: _omitted, ...absent } = clone(request);
    expect(parsePermissionRequest(absent)).toEqual(request);
    expect(hashPermissionRequest(absent)).toBe(hashPermissionRequest(request));

    const hosted = {
      ...clone(request),
      sessionSigner: { mode: "oaath_hosted", providerId: "kms-primary" },
    };
    const parsed = parsePermissionRequest(hosted);
    expect(parsed.sessionSigner).toEqual({ mode: "oaath_hosted", providerId: "kms-primary" });
    expect(Object.isFrozen(parsed.sessionSigner)).toBe(true);
    // The owner's approval binds the custody model: mode, provider, and
    // presence each change the hash the decision commits to.
    const hostedHash = hashPermissionRequest(hosted);
    expect(hostedHash).not.toBe(hashPermissionRequest(request));
    expect(
      hashPermissionRequest({
        ...clone(request),
        sessionSigner: { mode: "application_backend", providerId: "kms-primary" },
      }),
    ).not.toBe(hostedHash);
    expect(
      hashPermissionRequest({
        ...clone(request),
        sessionSigner: { mode: "oaath_hosted", providerId: "kms-secondary" },
      }),
    ).not.toBe(hostedHash);
  });

  it.each([
    // Frontend custody has exactly one non-null spelling: absence. An explicit
    // frontend object would mint a second encoding of the same fact.
    [{ mode: "frontend", providerId: null }],
    [{ mode: "owner_hosted", providerId: "kms-primary" }],
    [{ mode: "oaath_hosted", providerId: "" }],
    [{ mode: "oaath_hosted" }],
    [{ mode: "oaath_hosted", providerId: "kms-primary", extra: 1 }],
    ["oaath_hosted"],
  ])("refuses a malformed session-signer declaration", (sessionSigner) => {
    expect(() => parsePermissionRequest({ ...clone(request), sessionSigner })).toThrowError(
      expect.objectContaining({ code: "permission_request_invalid" }),
    );
  });
});

describe("PermissionDecision current codec", () => {
  it("owns closed approve/reject records and hashes every authority-bearing field", () => {
    expect(OAATH_PERMISSION_DECISION_VERSION).toBe("oaath.permission-decision/v1");
    expect(OAATH_PERMISSION_DECISION_HASH_DOMAIN).toBe("@oaath/protocol:permission-decision");
    for (const decision of [approve(), reject()]) {
      const parsed = parsePermissionDecision(clone(decision));
      expect(parsed).toEqual(decision);
      expect(Object.isFrozen(parsed)).toBe(true);
      expect(parsePermissionDecision(clone(parsed))).toEqual(parsed);
      expect(encodePermissionDecision(clone(parsed))).toBe(encodePermissionDecision(parsed));
      expect(hashPermissionDecision(clone(parsed))).toBe(hashPermissionDecision(parsed));
    }
    expect(hashPermissionDecision(approve())).toBe(
      "0x278654d2af0f368a267632aa9f49f03205ae6f2026705593ece39a09bfe72b2c",
    );
    expect(hashPermissionDecision(reject())).toBe(
      "0x951ceab50e2600891bbf97b7721003ec7a6d0ed5596f4f7f21a264b4e48f25b6",
    );
    expect(hashPermissionDecision(approve({ capabilityHash: `0x${"66".repeat(32)}` }))).not.toBe(
      hashPermissionDecision(approve()),
    );
    expect(
      hashPermissionDecision(
        approve({ approvedPolicy: { ...clone(policy), perChainOperationLimit: 9 } }),
      ),
    ).not.toBe(hashPermissionDecision(approve()));
  });

  it("rejects contradictory variants, hashes, numeric aliases, extras, and hostile fields", () => {
    const accessor = clone(approve()) as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "decidedAt", { enumerable: true, get: () => 120 });
    const invalidDecisions: unknown[] = [
      { ...clone(approve()), version: "oaath.permission-decision/v0" },
      { ...clone(approve()), kind: "allow" },
      { ...clone(approve()), requestId: " request" },
      { ...clone(approve()), requestHash: `0x${"AA".repeat(32)}` },
      { ...clone(approve()), capabilityHash: `0x${"00".repeat(32)}` },
      { ...clone(approve()), capabilityHash: "0x12" },
      { ...clone(approve()), decidedAt: -0 },
      { ...clone(approve()), decidedAt: 1.5 },
      { ...clone(approve()), decidedAt: 2 ** 48 },
      { ...clone(approve()), chainId: 1 },
      { ...clone(reject()), approvedPolicy: policy },
      { ...clone(reject()), capabilityHash },
      { ...clone(reject()), reason: "diagnostic prose" },
      { ...clone(reject()), [Symbol("hidden")]: true },
      accessor,
    ];
    for (const value of invalidDecisions) {
      expectProtocolError(() => parsePermissionDecision(value), "permission_decision_invalid");
    }
  });
});

describe("permission request/decision binding", () => {
  it("applies a preserving approval and commits the full decision hash", () => {
    const decision = approve();
    const result = applyPermissionDecision(applyInput(decision));
    expect(result).toMatchObject({
      status: "applied",
      decisionHash: hashPermissionDecision(decision),
      grant: {
        state: "approved",
        revision: 1,
        identity: { policyHash: hashGrantPolicy(request.policy) },
        approval: {
          approvalHash: hashPermissionDecision(decision),
          capabilityHash,
          approvedAt: 120,
        },
      },
    });
  });

  it("applies an attenuated policy without replacing the immutable requested-policy identity", () => {
    const approvedPolicy: GrantPolicy = {
      ...clone(policy),
      calls: [
        {
          ...clone(basePolicyCall),
          valueLimit: "50",
          argumentEquals: [{ index: 0, value: argumentWord }],
        },
      ],
      validAfter: 110,
      validUntil: 180,
      perChainOperationLimit: 5,
    };
    const decision = approve({ approvedPolicy });
    const result = applyPermissionDecision(applyInput(decision));
    expect(result.status).toBe("applied");
    expect(result.grant.identity.policyHash).toBe(hashGrantPolicy(policy));
    expect(result.grant.identity.policyHash).not.toBe(hashGrantPolicy(approvedPolicy));
    expect(result.grant.approval?.approvalHash).toBe(hashPermissionDecision(decision));
    expect("approvedPolicy" in result.grant).toBe(false);
  });

  it("applies a matching rejection terminally with no authority or materialization", () => {
    const decision = reject();
    const result = applyPermissionDecision(applyInput(decision));
    expect(result).toEqual({
      status: "applied",
      decisionHash: hashPermissionDecision(decision),
      grant: {
        ...result.grant,
        state: "rejected",
        revision: 1,
        approval: null,
        capabilityInvalidation: null,
        materializations: [],
        terminal: { kind: "rejected", recordedAt: 120 },
      },
    });
  });

  it("replays the exact decision without a revision bump, including after later state and expiry", () => {
    const approvalDecision = approve();
    const approved = applyPermissionDecision(applyInput(approvalDecision)).grant;
    const active = advanceGrant(approved, {
      type: "activate",
      identity: approved.identity,
      activatedAt: 130,
    });
    const expired = advanceGrant(active, {
      type: "expire",
      identity: active.identity,
      expiredAt: 200,
    });
    const replayedApproval = applyPermissionDecision(
      applyInput(approvalDecision, { grant: clone(expired), evaluatedAt: 250 }),
    );
    expect(replayedApproval).toMatchObject({
      status: "replayed",
      grant: { state: "expired", revision: 3 },
    });
    expect(replayedApproval.grant).toEqual(expired);

    const rejectionDecision = reject();
    const rejected = applyPermissionDecision(applyInput(rejectionDecision)).grant;
    const replayedRejection = applyPermissionDecision(
      applyInput(rejectionDecision, { grant: clone(rejected), evaluatedAt: 250 }),
    );
    expect(replayedRejection).toMatchObject({ status: "replayed", grant: { revision: 1 } });
    expect(replayedRejection.grant).toEqual(rejected);
  });

  it("rejects any second different decision before changing the accepted Grant", () => {
    const acceptedApproval = applyPermissionDecision(applyInput(approve())).grant;
    const approvalConflicts: PermissionDecision[] = [
      approve({ decidedAt: 121 }),
      approve({ capabilityHash: `0x${"66".repeat(32)}` }),
      approve({ approvedPolicy: { ...clone(policy), perChainOperationLimit: 9 } }),
      reject(),
    ];
    for (const decision of approvalConflicts) {
      expectProtocolError(
        () => applyPermissionDecision(applyInput(decision, { grant: acceptedApproval })),
        "permission_decision_conflict",
      );
      expect(acceptedApproval).toMatchObject({ state: "approved", revision: 1 });
    }

    const acceptedRejection = applyPermissionDecision(applyInput(reject())).grant;
    for (const decision of [reject({ decidedAt: 121 }), approve()]) {
      expectProtocolError(
        () => applyPermissionDecision(applyInput(decision, { grant: acceptedRejection })),
        "permission_decision_conflict",
      );
      expect(acceptedRejection).toMatchObject({ state: "rejected", revision: 1 });
    }
  });

  it("keeps missing, timeout, and unreadable observations pending without mutation", () => {
    const grant = createGrantFromPermissionRequest(request);
    for (const reason of ["missing", "timeout", "unreadable"] as const) {
      const result = applyPermissionDecision({
        request,
        grant,
        observation: { status: "unavailable", reason },
        evaluatedAt: 500,
      });
      expect(result).toEqual({ status: "pending", reason, grant });
      expect(result.grant).toMatchObject({ state: "requested", revision: 0 });
    }
  });

  it("rejects request, Grant, request-hash, and identity substitution", () => {
    const baseGrant = createGrantFromPermissionRequest(request);
    const wrongGrant = createGrant({
      identity: {
        ...baseGrant.identity,
        application: { ...request.application, clientId: "other" },
      },
      requestedAt: request.requestedAt,
      expiresAt: request.expiresAt,
    });
    expectProtocolError(
      () => applyPermissionDecision(applyInput(approve(), { grant: wrongGrant })),
      "permission_request_binding_mismatch",
    );

    for (const decision of [
      approve({ requestId: "another-request" }),
      approve({ requestHash: `0x${"77".repeat(32)}` }),
    ]) {
      expectProtocolError(
        () => applyPermissionDecision(applyInput(decision)),
        "permission_decision_binding_mismatch",
      );
    }

    const substitutions: PermissionRequest[] = [
      { ...clone(request), requestId: "another-request" },
      { ...clone(request), application: { ...request.application, deviceId: "another-device" } },
      {
        ...clone(request),
        logicalAccount: { ...request.logicalAccount, accountIndex: "8" },
      },
      {
        ...clone(request),
        operatorCredential: {
          version: "oaath.operator-credential-profile/v1",
          kind: "ecdsa",
          address: ownerAddress,
        },
      },
      { ...clone(request), policy: { ...clone(policy), perChainOperationLimit: 9 } },
      { ...clone(request), requestedAt: 101 },
      { ...clone(request), expiresAt: 201 },
    ];
    for (const changedRequest of substitutions) {
      expectProtocolError(
        () => applyPermissionDecision(applyInput(approve(), { request: changedRequest })),
        "permission_request_binding_mismatch",
      );
    }
  });

  it("rejects widening, stale, expired, and future first decisions", () => {
    const widenings: GrantPolicy[] = [
      { ...clone(policy), perChainOperationLimit: 11 },
      { ...clone(policy), validAfter: 99 },
      { ...clone(policy), validUntil: 191 },
      { ...clone(policy), calls: [{ ...clone(basePolicyCall), valueLimit: "101" }] },
    ];
    for (const approvedPolicy of widenings) {
      expectProtocolError(
        () => applyPermissionDecision(applyInput(approve({ approvedPolicy }))),
        "permission_policy_widening",
      );
    }

    const staleCases: readonly [PermissionDecision, number][] = [
      [approve({ decidedAt: 99 }), 120],
      [approve({ decidedAt: 200 }), 200],
      [approve({ decidedAt: 121 }), 120],
      [approve(), 200],
      [approve({ approvedPolicy: { ...clone(policy), validUntil: 119 } }), 120],
    ];
    for (const [decision, evaluatedAt] of staleCases) {
      expectProtocolError(
        () => applyPermissionDecision(applyInput(decision, { evaluatedAt })),
        "permission_decision_stale",
      );
    }
  });

  it("rejects hostile observations and diagnostic or transport objects as decisions", () => {
    const invalidInputs: unknown[] = [
      { ...applyInput(approve()), extra: true },
      { ...applyInput(approve()), evaluatedAt: -0 },
      { ...applyInput(approve()), observation: null },
      { ...applyInput(approve()), observation: { status: "timeout", message: "timed out" } },
      {
        ...applyInput(approve()),
        observation: { status: "unavailable", reason: "transport_error" },
      },
      {
        ...applyInput(approve()),
        observation: { status: "unavailable", reason: "timeout", message: "diagnostic" },
      },
    ];
    for (const value of invalidInputs) {
      expectProtocolError(
        () => applyPermissionDecision(value),
        "permission_protocol_input_invalid",
      );
    }
  });
});

describe("permission protocol properties", () => {
  it("keeps request and decision hashes deterministic across JSON recreation", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 100, max: 10_000 }),
        fc.integer({ min: 2, max: 1_000 }),
        fc.integer({ min: 1, max: 100 }),
        (requestedAt, lifetime, limit) => {
          const generated: PermissionRequest = {
            ...clone(request),
            requestId: `request-${requestedAt}-${lifetime}-${limit}`,
            requestedAt,
            expiresAt: requestedAt + lifetime,
            policy: {
              ...clone(policy),
              validAfter: requestedAt,
              validUntil: requestedAt + lifetime - 1,
              perChainOperationLimit: limit,
            },
          };
          const decision: ApprovePermissionDecision = {
            ...approve(),
            requestId: generated.requestId,
            requestHash: hashPermissionRequest(generated),
            decidedAt: requestedAt,
            approvedPolicy: generated.policy,
          };
          expect(hashPermissionRequest(clone(generated))).toBe(hashPermissionRequest(generated));
          expect(hashPermissionDecision(clone(decision))).toBe(hashPermissionDecision(decision));
        },
      ),
    );
  });

  it("keeps exact replay idempotent for generated decision times", () => {
    fc.assert(
      fc.property(fc.integer({ min: 100, max: 189 }), (decidedAt) => {
        const decision = approve({ decidedAt });
        const first = applyPermissionDecision(
          applyInput(decision, { evaluatedAt: Math.max(120, decidedAt) }),
        );
        const replay = applyPermissionDecision(
          applyInput(decision, { grant: clone(first.grant), evaluatedAt: 250 }),
        );
        expect(replay).toMatchObject({
          status: "replayed",
          decisionHash: hashPermissionDecision(decision),
          grant: { revision: 1 },
        });
        expect(replay.grant).toEqual(first.grant);
      }),
    );
  });

  it("rejects generated substitutions across every request-to-Grant binding", () => {
    const substitutions: readonly RequestSubstitution[] = [
      "application_id",
      "client_id",
      "origin",
      "device_id",
      "logical_account",
      "owner_credential",
      "operator_credential",
      "policy",
      "request_id",
      "requested_at",
      "expires_at",
    ];
    for (const kind of substitutions) {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 1_000 }), (seed) => {
          const grant = createGrantFromPermissionRequest(request);
          const before = clone(grant);
          expectProtocolError(
            () =>
              applyPermissionDecision(
                applyInput(approve(), { request: substituteRequest(kind, seed), grant }),
              ),
            "permission_request_binding_mismatch",
          );
          expect(grant).toEqual(before);
        }),
      );
    }
  });

  it("rejects generated decision request-ID/hash substitutions without Grant mutation", () => {
    for (const kind of ["request_id", "request_hash"] as const) {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 250 }), (seed) => {
          const capabilityByte = seed === 0x55 ? 0xfe : seed;
          const byte = capabilityByte.toString(16).padStart(2, "0");
          const decision =
            kind === "request_id"
              ? approve({ requestId: `another-${seed}` })
              : approve({ requestHash: `0x${byte.repeat(32)}` });
          const grant = createGrantFromPermissionRequest(request);
          const before = clone(grant);
          expectProtocolError(
            () => applyPermissionDecision(applyInput(decision, { grant })),
            "permission_decision_binding_mismatch",
          );
          expect(grant).toEqual(before);
        }),
      );
    }
  });

  it("rejects generated second-decision field changes without altering accepted authority", () => {
    for (const kind of ["capability", "policy", "time", "kind"] as const) {
      fc.assert(
        fc.property(fc.integer({ min: 1, max: 250 }), (seed) => {
          const accepted = applyPermissionDecision(applyInput(approve())).grant;
          const before = clone(accepted);
          const capabilityByte = seed === 0x55 ? 0xfe : seed;
          const byte = capabilityByte.toString(16).padStart(2, "0");
          const changed: PermissionDecision =
            kind === "capability"
              ? approve({ capabilityHash: `0x${byte.repeat(32)}` })
              : kind === "policy"
                ? approve({
                    approvedPolicy: {
                      ...clone(policy),
                      perChainOperationLimit: (seed % 9) + 1,
                    },
                  })
                : kind === "time"
                  ? approve({ decidedAt: (seed % 69) + 121 })
                  : reject();
          expectProtocolError(
            () => applyPermissionDecision(applyInput(changed, { grant: accepted })),
            "permission_decision_conflict",
          );
          expect(accepted).toEqual(before);
        }),
      );
    }
  });
});
