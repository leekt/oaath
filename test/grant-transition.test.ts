import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  advanceGrant,
  createGrant,
  type Grant,
  type GrantIdentity,
  type GrantTransition,
  OgpGrantError,
  parseGrant,
} from "../src/index.js";

const identity: GrantIdentity = {
  grantId: "transition-grant",
  chainScope: "all",
  application: {
    applicationId: "ogp-tests",
    clientId: "grant-transitions",
    origin: "https://transitions.example",
    deviceId: "transition-device",
  },
  logicalAccount: {
    version: "ogp.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
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

function binding(chainId: number) {
  return {
    chainId,
    account: `0x${String((chainId % 8) + 1).repeat(40)}` as const,
    permissionId: `0x${chainId.toString(16).padStart(8, "0")}` as const,
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

function requested(): Grant {
  return createGrant({ identity, requestedAt: 10, expiresAt: 100 });
}

function approved(): Grant {
  return advanceGrant(requested(), { type: "approve", identity, approval });
}

function active(): Grant {
  return advanceGrant(approved(), { type: "activate", identity, activatedAt: 30 });
}

function addUnmaterialized(grant: Grant, chainId: number, recordedAt: number): Grant {
  return advanceGrant(grant, {
    type: "record_unmaterialized",
    identity,
    binding: binding(chainId),
    recordedAt,
  });
}

function beginMaterialization(grant: Grant, chainId: number, startedAt: number): Grant {
  return advanceGrant(grant, {
    type: "begin_materialization",
    identity,
    binding: binding(chainId),
    startedAt,
  });
}

function install(grant: Grant, chainId: number, observedAt: number): Grant {
  return advanceGrant(grant, {
    type: "record_installed",
    identity,
    binding: binding(chainId),
    installation: present(chainId, 10, observedAt),
  });
}

function beginRevocation(grant: Grant, at: number): Grant {
  return advanceGrant(grant, {
    type: "begin_revocation",
    identity,
    revocationStartedAt: at,
  });
}

function beginChainRevocation(grant: Grant, chainId: number, at: number): Grant {
  return advanceGrant(grant, {
    type: "begin_chain_revocation",
    identity,
    binding: binding(chainId),
    startedAt: at,
  });
}

function revokeChain(grant: Grant, chainId: number, at: number): Grant {
  return advanceGrant(grant, {
    type: "record_chain_revoked",
    identity,
    binding: binding(chainId),
    removal: absent(chainId, 11, at),
  });
}

function invalidateCapability(grant: Grant, at: number): Grant {
  return advanceGrant(grant, {
    type: "record_capability_invalidated",
    identity,
    invalidation: {
      kind: "approval_capability_invalidated",
      capabilityHash: approval.capabilityHash,
      evidenceHash: `0x${"88".repeat(32)}`,
      invalidatedAt: at,
    },
  });
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

describe("Grant transitions", () => {
  it("materializes independent chains after one approval and revokes them after reload", () => {
    let grant = active();
    expect(grant).toMatchObject({ state: "active", revision: 2, materializations: [] });

    grant = addUnmaterialized(grant, 137, 31);
    grant = beginMaterialization(grant, 137, 32);
    grant = install(grant, 137, 33);
    grant = addUnmaterialized(grant, 1, 34);
    grant = beginMaterialization(grant, 1, 35);

    grant = beginRevocation(grant, 40);
    expect(grant).toMatchObject({
      state: "revoking",
      materializations: [
        { chainId: 1, state: "installing" },
        { chainId: 137, state: "installed" },
      ],
    });

    grant = parseGrant(clone(grant));
    grant = install(grant, 1, 41);
    grant = beginChainRevocation(grant, 1, 42);
    grant = revokeChain(grant, 1, 43);
    grant = beginChainRevocation(grant, 137, 44);
    grant = advanceGrant(grant, {
      type: "record_unreadable",
      identity,
      binding: binding(137),
      observedAt: 45,
      reason: "provider_unavailable",
    });
    expect(grant).toMatchObject({
      materializations: [
        { chainId: 1, state: "revoked" },
        { chainId: 137, state: "unreadable", priorState: "revoking" },
      ],
    });

    grant = parseGrant(clone(grant));
    expectGrantError(() => beginChainRevocation(grant, 137, 46), "grant_transition_forbidden");
    grant = revokeChain(grant, 137, 46);
    grant = invalidateCapability(grant, 47);
    grant = advanceGrant(grant, {
      type: "complete_revocation",
      identity,
      revokedAt: 48,
    });

    expect(grant).toMatchObject({
      state: "revoked",
      revision: 16,
      terminal: { kind: "revoked", recordedAt: 48 },
      materializations: [{ state: "revoked" }, { state: "revoked" }],
    });
    expect(Object.isFrozen(grant)).toBe(true);
    expect(Object.isFrozen(grant.materializations)).toBe(true);
    expect("operationId" in grant).toBe(false);
    expect("nonce" in grant).toBe(false);
  });

  it("keeps approved separate from active and rejected terminal", () => {
    const waiting = approved();
    expect(waiting).toMatchObject({ state: "approved", materializations: [] });
    expectGrantError(() => addUnmaterialized(waiting, 1, 21), "grant_transition_forbidden");

    const rejected = advanceGrant(requested(), {
      type: "reject",
      identity,
      rejectedAt: 20,
    });
    expect(rejected).toMatchObject({ state: "rejected", revision: 1 });
    expectGrantError(
      () => advanceGrant(rejected, { type: "approve", identity, approval }),
      "grant_transition_forbidden",
    );
  });

  it("records support discovery without creating a chain allowlist", () => {
    let grant = advanceGrant(active(), {
      type: "record_unsupported",
      identity,
      chainId: 137,
      recordedAt: 31,
      reason: "runtime_unsupported",
    });
    expect(grant).toMatchObject({
      identity: { chainScope: "all" },
      materializations: [{ chainId: 137, state: "unsupported" }],
    });
    grant = addUnmaterialized(grant, 137, 32);
    expect(grant).toMatchObject({
      materializations: [{ chainId: 137, state: "unmaterialized" }],
    });
    expect("chainIds" in grant.identity).toBe(false);
  });

  it("blocks new installation as soon as global revocation starts", () => {
    let grant = addUnmaterialized(active(), 1, 31);
    grant = beginRevocation(grant, 32);
    expectGrantError(() => beginMaterialization(grant, 1, 33), "grant_transition_forbidden");
    expectGrantError(() => addUnmaterialized(grant, 137, 33), "grant_transition_forbidden");
  });

  it("requires positive child removal and capability invalidation before completion", () => {
    let grant = install(beginMaterialization(addUnmaterialized(active(), 1, 31), 1, 32), 1, 33);
    grant = beginRevocation(grant, 40);
    expectGrantError(
      () => advanceGrant(grant, { type: "complete_revocation", identity, revokedAt: 41 }),
      "grant_transition_forbidden",
    );

    grant = beginChainRevocation(grant, 1, 41);
    grant = advanceGrant(grant, {
      type: "record_unreadable",
      identity,
      binding: binding(1),
      observedAt: 42,
      reason: "canonicality_unproven",
    });
    grant = invalidateCapability(grant, 43);
    expectGrantError(
      () => advanceGrant(grant, { type: "complete_revocation", identity, revokedAt: 44 }),
      "grant_transition_forbidden",
    );

    expectGrantError(() => beginChainRevocation(grant, 1, 44), "grant_transition_forbidden");
    grant = revokeChain(grant, 1, 44);
    const revoked = advanceGrant(grant, {
      type: "complete_revocation",
      identity,
      revokedAt: 45,
    });
    expect(revoked.state).toBe("revoked");
  });

  it("does not close an in-flight installation from absence evidence alone", () => {
    let grant = beginMaterialization(addUnmaterialized(active(), 1, 31), 1, 32);
    grant = beginChainRevocation(beginRevocation(grant, 40), 1, 41);
    expectGrantError(() => revokeChain(grant, 1, 42), "grant_transition_forbidden");

    grant = advanceGrant(grant, {
      type: "record_unreadable",
      identity,
      binding: binding(1),
      observedAt: 42,
      reason: "provider_unavailable",
    });
    expectGrantError(() => revokeChain(grant, 1, 43), "grant_transition_forbidden");
  });

  it("rejects cross-chain, account, permission, and Grant identity substitution", () => {
    const installing = beginMaterialization(addUnmaterialized(active(), 1, 31), 1, 32);
    for (const changed of [
      { chainId: 137 },
      { account: binding(2).account },
      { permissionId: binding(2).permissionId },
    ]) {
      expectGrantError(
        () =>
          advanceGrant(installing, {
            type: "record_installed",
            identity,
            binding: binding(1),
            installation: { ...present(1, 10, 33), ...changed },
          }),
        "grant_identity_mismatch",
      );
    }
    expectGrantError(
      () =>
        advanceGrant(installing, {
          type: "record_installed",
          identity: { ...identity, grantId: "other" },
          binding: binding(1),
          installation: present(1, 10, 33),
        }),
      "grant_identity_mismatch",
    );

    const revoking = beginChainRevocation(beginRevocation(installing, 40), 1, 41);
    expectGrantError(
      () =>
        advanceGrant(revoking, {
          type: "record_chain_revoked",
          identity,
          binding: binding(1),
          removal: absent(2, 11, 42),
        }),
      "grant_identity_mismatch",
    );
    expectGrantError(
      () =>
        advanceGrant(beginRevocation(active(), 40), {
          type: "record_capability_invalidated",
          identity,
          invalidation: {
            kind: "approval_capability_invalidated",
            capabilityHash: `0x${"99".repeat(32)}`,
            evidenceHash: `0x${"88".repeat(32)}`,
            invalidatedAt: 41,
          },
        }),
      "grant_identity_mismatch",
    );
  });

  it("rejects application, client, origin, and device substitution before authority changes", () => {
    const applicationSubstitutions = [
      { ...identity.application, applicationId: "other-app" },
      { ...identity.application, clientId: "other-client" },
      { ...identity.application, origin: "https://other.example" },
      { ...identity.application, deviceId: "other-device" },
    ];

    for (const application of applicationSubstitutions) {
      const substitutedIdentity = { ...identity, application };
      expectGrantError(
        () =>
          advanceGrant(requested(), {
            type: "approve",
            identity: substitutedIdentity,
            approval,
          }),
        "grant_identity_mismatch",
      );
      expectGrantError(
        () =>
          advanceGrant(active(), {
            type: "record_unmaterialized",
            identity: substitutedIdentity,
            binding: binding(1),
            recordedAt: 31,
          }),
        "grant_identity_mismatch",
      );
      expectGrantError(
        () =>
          advanceGrant(active(), {
            type: "begin_revocation",
            identity: substitutedIdentity,
            revocationStartedAt: 40,
          }),
        "grant_identity_mismatch",
      );
    }

    fc.assert(
      fc.property(
        fc.constantFrom("applicationId", "clientId", "origin", "deviceId" as const),
        fc.integer({ min: 1, max: 1_000_000 }),
        (field, seed) => {
          const value = field === "origin" ? `https://app-${seed}.example` : `identity-${seed}`;
          const application = { ...identity.application, [field]: value };
          expectGrantError(
            () =>
              advanceGrant(requested(), {
                type: "approve",
                identity: { ...identity, application },
                approval,
              }),
            "grant_identity_mismatch",
          );
        },
      ),
      { numRuns: 64 },
    );
  });

  it("rejects logical-account and credential-profile substitution", () => {
    const substitutions: GrantIdentity[] = [
      {
        ...identity,
        logicalAccount: { ...identity.logicalAccount, accountIndex: "1" },
      },
      {
        ...identity,
        logicalAccount: { ...identity.logicalAccount, factoryRoute: "kernel_factory" },
      },
      {
        ...identity,
        logicalAccount: {
          ...identity.logicalAccount,
          ownerCredential: {
            version: "ogp.owner-credential-profile/v1",
            kind: "ecdsa",
            address: `0x${"44".repeat(20)}`,
          },
        },
      },
      {
        ...identity,
        operatorCredential: {
          version: "ogp.operator-credential-profile/v1",
          kind: "ecdsa",
          address: `0x${"55".repeat(20)}`,
        },
      },
    ];

    for (const substitutedIdentity of substitutions) {
      expectGrantError(
        () =>
          advanceGrant(requested(), {
            type: "approve",
            identity: substitutedIdentity,
            approval,
          }),
        "grant_identity_mismatch",
      );
    }
  });

  it("preserves strongest evidence through unreadable observations", () => {
    let grant = install(beginMaterialization(addUnmaterialized(active(), 1, 31), 1, 32), 1, 33);
    grant = advanceGrant(grant, {
      type: "record_unreadable",
      identity,
      binding: binding(1),
      observedAt: 34,
      reason: "state_invalid",
    });
    expect(grant).toMatchObject({
      materializations: [
        {
          state: "unreadable",
          priorState: "installed",
          installation: { kind: "permission_present", observedAt: 33 },
        },
      ],
    });
    grant = install(grant, 1, 35);
    expect(grant).toMatchObject({ state: "active", materializations: [{ state: "installed" }] });
  });

  it("rejects time regression, authority work at expiry, and contradictory block evidence", () => {
    expectGrantError(
      () => advanceGrant(active(), { type: "begin_revocation", identity, revocationStartedAt: 29 }),
      "grant_transition_invalid",
    );
    expectGrantError(() => addUnmaterialized(active(), 1, 100), "grant_transition_invalid");
    expectGrantError(
      () => advanceGrant(active(), { type: "expire", identity, expiredAt: 99 }),
      "grant_transition_invalid",
    );

    let grant = install(beginMaterialization(addUnmaterialized(active(), 1, 31), 1, 32), 1, 33);
    expectGrantError(
      () =>
        advanceGrant(grant, {
          type: "record_installed",
          identity,
          binding: binding(1),
          installation: { ...present(1, 10, 34), blockHash: `0x${"99".repeat(32)}` },
        }),
      "grant_transition_invalid",
    );
    grant = beginChainRevocation(beginRevocation(grant, 40), 1, 41);
    expectGrantError(
      () =>
        advanceGrant(grant, {
          type: "record_chain_revoked",
          identity,
          binding: binding(1),
          removal: absent(1, 10, 42),
        }),
      "grant_transition_invalid",
    );
  });

  it("expires every nonterminal source without erasing unfinished authority", () => {
    const sources = [requested(), approved(), active(), beginRevocation(active(), 40)];
    for (const source of sources) {
      const expired = advanceGrant(source, { type: "expire", identity, expiredAt: 100 });
      expect(expired).toMatchObject({
        state: "expired",
        terminal: { kind: "expired", from: source.state },
      });
    }

    let occupied = install(beginMaterialization(addUnmaterialized(active(), 1, 31), 1, 32), 1, 33);
    occupied = beginRevocation(occupied, 40);
    const expired = advanceGrant(occupied, { type: "expire", identity, expiredAt: 100 });
    expect(expired).toMatchObject({
      state: "expired",
      materializations: [{ state: "installed", installation: { kind: "permission_present" } }],
    });
  });

  it("captures transitions exactly and never invokes hostile accessors", () => {
    const grant = active();
    expectGrantError(
      () =>
        advanceGrant(grant, {
          type: "record_unsupported",
          identity,
          chainId: 1,
          recordedAt: 31,
          reason: "runtime_unsupported",
          operationId: "forbidden",
        }),
      "grant_transition_invalid",
    );

    let calls = 0;
    const transition: Record<string, unknown> = {
      type: "record_unsupported",
      identity,
      chainId: 1,
      reason: "runtime_unsupported",
    };
    Object.defineProperty(transition, "recordedAt", {
      enumerable: true,
      get() {
        calls += 1;
        return 31;
      },
    });
    expectGrantError(() => advanceGrant(grant, transition), "grant_transition_invalid");
    expect(calls).toBe(0);

    expectGrantError(
      () =>
        advanceGrant(grant, {
          type: "record_unsupported",
          identity,
          chainId: 1,
          recordedAt: 31,
          reason: "runtime_unsupported",
          [Symbol("hidden")]: true,
        }),
      "grant_transition_invalid",
    );

    const aliasedIdentity = clone(identity) as unknown as Record<string, unknown>;
    const logicalAccount = aliasedIdentity.logicalAccount as Record<string, unknown>;
    aliasedIdentity.operatorCredential = logicalAccount.ownerCredential;
    expectGrantError(
      () =>
        advanceGrant(grant, {
          type: "record_unsupported",
          identity: aliasedIdentity,
          chainId: 1,
          recordedAt: 31,
          reason: "runtime_unsupported",
        }),
      "grant_transition_invalid",
    );

    const secret = "do-not-leak-transition-secret";
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new OgpGrantError("grant_transition_invalid", secret);
        },
      },
    );
    try {
      advanceGrant(grant, hostile);
    } catch (error) {
      expect((error as Error).message).not.toContain(secret);
      return;
    }
    throw new Error("Expected hostile transition to reject");
  });

  it("rejects revision exhaustion before producing an unsafe alias", () => {
    const exhausted = { ...active(), revision: Number.MAX_SAFE_INTEGER };
    const restored = parseGrant(exhausted);
    expectGrantError(
      () =>
        advanceGrant(restored, {
          type: "record_unsupported",
          identity,
          chainId: 1,
          recordedAt: 31,
          reason: "runtime_unsupported",
        }),
      "grant_revision_exhausted",
    );
  });

  it("property-checks every forbidden Grant-state and transition-kind pair", () => {
    const rejected = advanceGrant(requested(), {
      type: "reject",
      identity,
      rejectedAt: 20,
    });
    const expired = advanceGrant(requested(), { type: "expire", identity, expiredAt: 100 });
    let revoked = beginRevocation(active(), 40);
    revoked = invalidateCapability(revoked, 41);
    revoked = advanceGrant(revoked, { type: "complete_revocation", identity, revokedAt: 42 });

    const transitions: readonly GrantTransition[] = [
      { type: "reject", identity, rejectedAt: 50 },
      { type: "approve", identity, approval: { ...approval, approvedAt: 50 } },
      { type: "activate", identity, activatedAt: 50 },
      { type: "expire", identity, expiredAt: 100 },
      {
        type: "record_unsupported",
        identity,
        chainId: 1,
        recordedAt: 50,
        reason: "runtime_unsupported",
      },
      {
        type: "record_unmaterialized",
        identity,
        binding: binding(1),
        recordedAt: 50,
      },
      { type: "begin_materialization", identity, binding: binding(1), startedAt: 50 },
      {
        type: "record_installed",
        identity,
        binding: binding(1),
        installation: present(1, 10, 50),
      },
      {
        type: "record_unreadable",
        identity,
        binding: binding(1),
        observedAt: 50,
        reason: "provider_unavailable",
      },
      { type: "begin_revocation", identity, revocationStartedAt: 50 },
      { type: "begin_chain_revocation", identity, binding: binding(1), startedAt: 50 },
      {
        type: "record_chain_revoked",
        identity,
        binding: binding(1),
        removal: absent(1, 11, 50),
      },
      {
        type: "record_capability_invalidated",
        identity,
        invalidation: {
          kind: "approval_capability_invalidated",
          capabilityHash: approval.capabilityHash,
          evidenceHash: `0x${"88".repeat(32)}`,
          invalidatedAt: 50,
        },
      },
      { type: "complete_revocation", identity, revokedAt: 50 },
    ];

    type StateCase = readonly [Grant, ReadonlySet<GrantTransition["type"]>];
    const allowed = (...types: GrantTransition["type"][]): ReadonlySet<GrantTransition["type"]> =>
      new Set(types);
    const states: readonly StateCase[] = [
      [requested(), allowed("reject", "approve", "expire")],
      [approved(), allowed("activate", "expire")],
      [
        active(),
        allowed(
          "expire",
          "record_unsupported",
          "record_unmaterialized",
          "begin_materialization",
          "record_installed",
          "record_unreadable",
          "begin_revocation",
        ),
      ],
      [
        beginRevocation(active(), 40),
        allowed(
          "expire",
          "record_installed",
          "record_unreadable",
          "begin_chain_revocation",
          "record_chain_revoked",
          "record_capability_invalidated",
          "complete_revocation",
        ),
      ],
      [rejected, allowed()],
      [expired, allowed()],
      [revoked, allowed()],
    ];

    fc.assert(
      fc.property(
        fc.constantFrom(...states),
        fc.constantFrom(...transitions),
        ([grant, allowedTypes], transition) => {
          if (allowedTypes.has(transition.type)) return;
          expectGrantError(() => advanceGrant(grant, transition), "grant_transition_forbidden");
        },
      ),
      { numRuns: 512 },
    );
  });
});
