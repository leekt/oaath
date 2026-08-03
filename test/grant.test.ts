import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { createGrant, type GrantIdentity, OgpGrantError, parseGrant } from "../src/index.js";

const identity: GrantIdentity = {
  grantId: "grant-all-chains",
  chainScope: "all",
  application: {
    applicationId: "ogp-tests",
    clientId: "grant-codec",
    origin: "https://grant.example",
    deviceId: "codec-device",
  },
  logicalAccount: {
    version: "ogp.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.3.3",
    factoryRoute: "meta_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "ogp.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"11".repeat(20)}`,
    },
  },
  operatorCredential: {
    version: "ogp.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"22".repeat(20)}`,
  },
  policyHash: `0x${"33".repeat(32)}`,
};

const approval = {
  approvalHash: `0x${"44".repeat(32)}` as const,
  capabilityHash: `0x${"55".repeat(32)}` as const,
  approvedAt: 20,
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function requestedRecord(): Record<string, unknown> {
  return clone(createGrant({ identity, requestedAt: 10, expiresAt: 100 })) as unknown as Record<
    string,
    unknown
  >;
}

function approvedRecord(): Record<string, unknown> {
  return {
    ...requestedRecord(),
    revision: 1,
    state: "approved",
    updatedAt: 20,
    approval: clone(approval),
  };
}

function activeRecord(
  materializations: readonly Record<string, unknown>[] = [],
  revision = 2,
  updatedAt = 30,
): Record<string, unknown> {
  return {
    ...approvedRecord(),
    revision,
    state: "active",
    updatedAt,
    activatedAt: 30,
    materializations,
  };
}

function binding(chainId: number): {
  chainId: number;
  account: `0x${string}`;
  permissionId: `0x${string}`;
} {
  return {
    chainId,
    account: `0x${String((chainId % 8) + 1).repeat(40)}`,
    permissionId: `0x${chainId.toString(16).padStart(8, "0")}`,
  };
}

function present(chainId: number, blockNumber: number, observedAt: number) {
  return {
    kind: "permission_present" as const,
    ...binding(chainId),
    blockNumber: String(blockNumber),
    blockHash: `0x${"66".repeat(32)}` as const,
    observedAt,
  };
}

function absent(chainId: number, blockNumber: number, observedAt: number) {
  return {
    kind: "permission_absent" as const,
    ...binding(chainId),
    blockNumber: String(blockNumber),
    blockHash: `0x${"77".repeat(32)}` as const,
    observedAt,
  };
}

function activeChildren(): Record<string, unknown>[] {
  return [
    { state: "unsupported", chainId: 1, updatedAt: 31, reason: "runtime_unsupported" },
    { state: "unmaterialized", ...binding(2), updatedAt: 32 },
    { state: "installing", ...binding(3), updatedAt: 33, startedAt: 33 },
    { state: "installed", ...binding(4), updatedAt: 34, installation: present(4, 10, 34) },
    {
      state: "unreadable",
      ...binding(5),
      updatedAt: 35,
      priorState: "installed",
      installation: present(5, 10, 34),
      reason: "provider_unavailable",
    },
  ];
}

function revokingChildren(): Record<string, unknown>[] {
  return [
    { state: "unsupported", chainId: 1, updatedAt: 31, reason: "policy_unsupported" },
    { state: "unmaterialized", ...binding(2), updatedAt: 32 },
    {
      state: "revoking",
      ...binding(3),
      updatedAt: 42,
      installation: null,
      startedAt: 42,
    },
    {
      state: "revoked",
      ...binding(4),
      updatedAt: 45,
      installation: present(4, 10, 34),
      removal: absent(4, 11, 45),
    },
    {
      state: "unreadable",
      ...binding(5),
      updatedAt: 46,
      priorState: "revoking",
      installation: present(5, 10, 35),
      reason: "canonicality_unproven",
    },
  ];
}

function revokingRecord(): Record<string, unknown> {
  return {
    ...activeRecord(),
    revision: 18,
    state: "revoking",
    updatedAt: 46,
    revocationStartedAt: 40,
    materializations: revokingChildren(),
  };
}

function revokedRecord(): Record<string, unknown> {
  return {
    ...activeRecord(),
    revision: 17,
    state: "revoked",
    updatedAt: 60,
    revocationStartedAt: 40,
    capabilityInvalidation: {
      kind: "approval_capability_invalidated",
      capabilityHash: approval.capabilityHash,
      evidenceHash: `0x${"88".repeat(32)}`,
      invalidatedAt: 55,
    },
    terminal: { kind: "revoked", recordedAt: 60 },
    materializations: [
      { state: "unsupported", chainId: 1, updatedAt: 31, reason: "runtime_unsupported" },
      { state: "unmaterialized", ...binding(2), updatedAt: 32 },
      {
        state: "revoked",
        ...binding(3),
        updatedAt: 50,
        installation: present(3, 10, 34),
        removal: absent(3, 12, 50),
      },
      {
        state: "revoked",
        ...binding(4),
        updatedAt: 51,
        installation: present(4, 10, 34),
        removal: absent(4, 11, 51),
      },
    ],
  };
}

function expectGrantError(action: () => unknown, code: OgpGrantError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OgpGrantError);
    expect((error as OgpGrantError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

function expectRecordInvalid(value: unknown): void {
  expectGrantError(() => parseGrant(value), "grant_record_invalid");
}

function child(record: Record<string, unknown>, index: number): Record<string, unknown> {
  const value = (record.materializations as Record<string, unknown>[])[index];
  if (!value) throw new Error(`Missing fixture child ${index}`);
  return value;
}

describe("Grant current codec", () => {
  it("creates one owned all-chain request with no approval-time chain list", () => {
    const mutableIdentity = clone(identity) as unknown as {
      grantId: string;
      application: { applicationId: string; origin: string };
      logicalAccount: { accountIndex: string };
    };
    const grant = createGrant({ identity: mutableIdentity, requestedAt: 10, expiresAt: 100 });
    mutableIdentity.grantId = "changed";
    mutableIdentity.application.applicationId = "changed-app";
    mutableIdentity.application.origin = "https://changed.example";
    mutableIdentity.logicalAccount.accountIndex = "7";

    expect(grant).toMatchObject({
      version: "ogp.grant/v3",
      state: "requested",
      revision: 0,
      identity: {
        grantId: identity.grantId,
        chainScope: "all",
        application: identity.application,
      },
      materializations: [],
    });
    expect("chainIds" in grant.identity).toBe(false);
    expect(Object.isFrozen(grant)).toBe(true);
    expect(Object.isFrozen(grant.identity)).toBe(true);
    expect(Object.isFrozen(grant.identity.application)).toBe(true);
    expect(Object.isFrozen(grant.identity.logicalAccount.ownerCredential)).toBe(true);
    expect(Object.isFrozen(grant.materializations)).toBe(true);
  });

  it("captures bounded application identity and canonicalizes only the origin", () => {
    const grant = createGrant({
      identity: {
        ...identity,
        application: {
          ...identity.application,
          origin: "https://GRANT.example:443/",
        },
      },
      requestedAt: 10,
      expiresAt: 100,
    });
    expect(grant.identity.application).toEqual({
      ...identity.application,
      origin: "https://grant.example",
    });

    for (const invalidOrigin of [
      "null",
      "file:///tmp/ogp",
      "https://grant.example/path",
      "https://grant.example?query=1",
      "https://grant.example#fragment",
      "https://user:secret@grant.example",
    ]) {
      expectGrantError(
        () =>
          createGrant({
            identity: {
              ...identity,
              application: { ...identity.application, origin: invalidOrigin },
            },
            requestedAt: 10,
            expiresAt: 100,
          }),
        "grant_input_invalid",
      );
    }

    for (const field of ["applicationId", "clientId", "deviceId"] as const) {
      const accepted = createGrant({
        identity: {
          ...identity,
          application: { ...identity.application, [field]: "a".repeat(64) },
        },
        requestedAt: 10,
        expiresAt: 100,
      });
      expect(accepted.identity.application[field]).toHaveLength(64);

      for (const invalidIdentifier of ["", "a".repeat(65), "NOT-CANONICAL"]) {
        expectGrantError(
          () =>
            createGrant({
              identity: {
                ...identity,
                application: { ...identity.application, [field]: invalidIdentifier },
              },
              requestedAt: 10,
              expiresAt: 100,
            }),
          "grant_input_invalid",
        );
      }
    }
  });

  it("round-trips every Grant state and all seven child shapes", () => {
    const requested = requestedRecord();
    const rejected = {
      ...requestedRecord(),
      revision: 1,
      state: "rejected",
      updatedAt: 20,
      terminal: { kind: "rejected", recordedAt: 20 },
    };
    const approved = approvedRecord();
    const active = activeRecord(activeChildren(), 13, 35);
    const revoking = revokingRecord();
    const revoked = revokedRecord();
    const expired = {
      ...activeRecord(
        [
          {
            state: "installed",
            ...binding(4),
            updatedAt: 34,
            installation: present(4, 10, 34),
          },
        ],
        6,
        100,
      ),
      state: "expired",
      terminal: { kind: "expired", from: "active", recordedAt: 100 },
    };

    for (const fixture of [requested, rejected, approved, active, revoking, revoked, expired]) {
      const restored = parseGrant(clone(fixture));
      expect(restored).toEqual(fixture);
      expect(Object.isFrozen(restored)).toBe(true);
      expect(Object.isFrozen(restored.materializations)).toBe(true);
    }
    expect(activeChildren().map((entry) => entry.state)).toEqual([
      "unsupported",
      "unmaterialized",
      "installing",
      "installed",
      "unreadable",
    ]);
    expect(revokingChildren().map((entry) => entry.state)).toContain("revoking");
    expect(revokingChildren().map((entry) => entry.state)).toContain("revoked");
  });

  it("requires positive removal for every authority child and capability invalidation", () => {
    const valid = revokedRecord();
    expect(parseGrant(valid).state).toBe("revoked");

    expectRecordInvalid({ ...valid, capabilityInvalidation: null });
    const noInstallation = clone(valid);
    child(noInstallation, 2).installation = null;
    expectRecordInvalid(noInstallation);
    expectRecordInvalid({
      ...valid,
      capabilityInvalidation: {
        ...(valid.capabilityInvalidation as Record<string, unknown>),
        capabilityHash: `0x${"99".repeat(32)}`,
      },
    });
    const unfinished = clone(valid);
    (unfinished.materializations as Record<string, unknown>[])[2] = {
      state: "revoking",
      ...binding(3),
      updatedAt: 50,
      installation: null,
      startedAt: 40,
    };
    expectRecordInvalid(unfinished);

    const unreadable = clone(valid);
    (unreadable.materializations as Record<string, unknown>[])[2] = {
      state: "unreadable",
      ...binding(3),
      updatedAt: 50,
      priorState: "revoking",
      installation: null,
      reason: "state_invalid",
    };
    expectRecordInvalid(unreadable);
  });

  it("retains installed authority while global revocation starts", () => {
    const installed = activeChildren()[3];
    if (!installed) throw new Error("Missing installed fixture child");
    const revoking = {
      ...activeRecord([installed], 5, 34),
      revision: 6,
      state: "revoking",
      updatedAt: 40,
      revocationStartedAt: 40,
    };
    expect(parseGrant(revoking)).toMatchObject({
      state: "revoking",
      materializations: [{ state: "installed" }],
    });
    expect(
      parseGrant({
        ...revoking,
        revision: 7,
        state: "expired",
        updatedAt: 100,
        terminal: { kind: "expired", from: "revoking", recordedAt: 100 },
      }),
    ).toMatchObject({ state: "expired", materializations: [{ state: "installed" }] });
    expectRecordInvalid({
      ...revoking,
      revision: 8,
      state: "revoked",
      updatedAt: 60,
      capabilityInvalidation: {
        kind: "approval_capability_invalidated",
        capabilityHash: approval.capabilityHash,
        evidenceHash: `0x${"88".repeat(32)}`,
        invalidatedAt: 55,
      },
      terminal: { kind: "revoked", recordedAt: 60 },
    });
  });

  it("does not borrow permission evidence across chains, accounts, or permissions", () => {
    const active = activeRecord(activeChildren(), 13, 35);
    for (const changed of [
      { chainId: 6 },
      { account: binding(6).account },
      { permissionId: binding(6).permissionId },
    ]) {
      const hostile = clone(active);
      const installed = child(hostile, 3);
      installed.installation = {
        ...(installed.installation as Record<string, unknown>),
        ...changed,
      };
      expectRecordInvalid(hostile);
    }
  });

  it("rejects retained installation evidence from before Grant activation", () => {
    const revoking = revokingRecord();
    child(revoking, 2).installation = present(3, 10, 29);
    revoking.revision = 19;

    const revoked = revokedRecord();
    (child(revoked, 3).installation as Record<string, unknown>).observedAt = 29;

    const unreadable = revokingRecord();
    (child(unreadable, 4).installation as Record<string, unknown>).observedAt = 29;

    for (const record of [revoking, revoked, unreadable]) expectRecordInvalid(record);
  });

  it("rejects non-current, inexact, aliased, and non-dense record graphs", () => {
    const active = activeRecord(activeChildren(), 13, 35);
    expectRecordInvalid({ ...active, version: "ogp.grant/v2" });
    expectRecordInvalid({ ...active, operationId: "forbidden" });
    const missing = { ...active };
    delete missing.updatedAt;
    expectRecordInvalid(missing);
    expectRecordInvalid({ ...active, [Symbol("hidden")]: true });

    const chainList = clone(active);
    (chainList.identity as Record<string, unknown>).chainIds = [1, 2];
    expectRecordInvalid(chainList);

    const unbound = clone(active);
    delete (unbound.identity as Record<string, unknown>).application;
    expectRecordInvalid(unbound);

    const extraApplicationField = clone(active);
    (
      (extraApplicationField.identity as Record<string, unknown>).application as Record<
        string,
        unknown
      >
    ).redirectUri = "https://grant.example/callback";
    expectRecordInvalid(extraApplicationField);

    const aliased = clone(active);
    child(aliased, 4).installation = child(aliased, 3).installation;
    expectRecordInvalid(aliased);

    const sparse = clone(active);
    sparse.materializations = new Array(1);
    expectRecordInvalid(sparse);
    const extra = clone(active);
    Object.defineProperty(extra.materializations, "extra", { enumerable: true, value: true });
    expectRecordInvalid(extra);

    let reads = 0;
    const accessor = clone(active);
    const first = (accessor.materializations as Record<string, unknown>[])[0];
    Object.defineProperty(accessor.materializations, "0", {
      enumerable: true,
      get() {
        reads += 1;
        return first;
      },
    });
    expectRecordInvalid(accessor);
    expect(reads).toBe(0);
  });

  it("rejects accessors without invocation and sanitizes reflection failures", () => {
    let calls = 0;
    const hostileIdentity = clone(identity) as unknown as Record<string, unknown>;
    Object.defineProperty(hostileIdentity, "policyHash", {
      enumerable: true,
      get() {
        calls += 1;
        return identity.policyHash;
      },
    });
    expectGrantError(
      () => createGrant({ identity: hostileIdentity, requestedAt: 10, expiresAt: 100 }),
      "grant_input_invalid",
    );
    expect(calls).toBe(0);

    let originCalls = 0;
    const hostileApplication = clone(identity) as unknown as Record<string, unknown>;
    const application = hostileApplication.application as Record<string, unknown>;
    Object.defineProperty(application, "origin", {
      enumerable: true,
      get() {
        originCalls += 1;
        return identity.application.origin;
      },
    });
    expectGrantError(
      () => createGrant({ identity: hostileApplication, requestedAt: 10, expiresAt: 100 }),
      "grant_input_invalid",
    );
    expect(originCalls).toBe(0);

    const secret = "do-not-leak-provider-secret";
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new OgpGrantError("grant_record_invalid", secret);
        },
      },
    );
    try {
      parseGrant(hostile);
    } catch (error) {
      expect(error).toBeInstanceOf(OgpGrantError);
      expect((error as Error).message).not.toContain(secret);
      return;
    }
    throw new Error("Expected hostile record to reject");
  });

  it("rejects scalar, chronology, state, evidence, and revision contradictions", () => {
    expectGrantError(
      () =>
        createGrant({
          identity: { ...identity, chainScope: "finite" },
          requestedAt: 10,
          expiresAt: 100,
        }),
      "grant_input_invalid",
    );
    expectGrantError(
      () => createGrant({ identity, requestedAt: -0, expiresAt: 100 }),
      "grant_input_invalid",
    );
    expectGrantError(
      () =>
        createGrant({
          identity: {
            ...identity,
            logicalAccount: { ...identity.logicalAccount, accountIndex: "00" },
          },
          requestedAt: 10,
          expiresAt: 100,
        }),
      "grant_input_invalid",
    );
    expectRecordInvalid({ ...requestedRecord(), revision: 1 });
    expectRecordInvalid({ ...approvedRecord(), updatedAt: 19 });
    expectRecordInvalid(activeRecord(activeChildren(), 12, 35));

    const earlyChild = activeRecord(activeChildren(), 13, 35);
    child(earlyChild, 0).updatedAt = 29;
    expectRecordInvalid(earlyChild);

    const sameBlockRemoval = revokedRecord();
    const revokedChild = child(sameBlockRemoval, 3);
    (revokedChild.removal as Record<string, unknown>).blockNumber = "10";
    expectRecordInvalid(sameBlockRemoval);

    const unreadableInstalling = activeRecord(activeChildren(), 13, 35);
    const unreadable = child(unreadableInstalling, 4);
    unreadable.priorState = "installing";
    expectRecordInvalid(unreadableInstalling);

    const atExpiry = activeRecord(activeChildren(), 13, 100);
    child(atExpiry, 4).updatedAt = 100;
    expectRecordInvalid(atExpiry);
  });

  it("property-checks sorted independent chain children without a support list", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.integer({ min: 1, max: 1_000_000 }), {
          minLength: 2,
          maxLength: 2,
        }),
        (chainIds) => {
          const sorted = [...chainIds].sort((left, right) => left - right);
          const children = sorted.map((chainId, index) => ({
            state: "unsupported",
            chainId,
            updatedAt: 31 + index,
            reason: "runtime_unsupported",
          }));
          const accepted = parseGrant(activeRecord(children, 4, 32));
          expect(accepted.identity.chainScope).toBe("all");
          expect(accepted.materializations.map((entry) => entry.chainId)).toEqual(sorted);
          expectRecordInvalid(activeRecord([...children].reverse(), 4, 32));
        },
      ),
      { numRuns: 64 },
    );
  });
});
