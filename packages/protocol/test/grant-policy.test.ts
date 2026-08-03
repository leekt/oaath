import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  encodeGrantPolicy,
  evaluateGrantPolicyCoverage,
  type GrantPolicy,
  type GrantPolicyCoverageInput,
  hashGrantPolicy,
  isGrantPolicyAttenuation,
  OAATH_GRANT_POLICY_HASH_DOMAIN,
  OAATH_GRANT_POLICY_USAGE_VERSION,
  OAATH_GRANT_POLICY_VERSION,
  OaathGrantPolicyError,
  parseGrantPolicy,
} from "../src/index.js";

const firstTarget = `0x${"11".repeat(20)}` as const;
const secondTarget = `0x${"22".repeat(20)}` as const;
const firstSelector = "0x12345678" as const;
const secondSelector = "0xabcdef01" as const;
const firstWord = `0x${"33".repeat(32)}` as const;
const secondWord = `0x${"44".repeat(32)}` as const;
const fillerWord = `0x${"55".repeat(32)}` as const;

const policy: GrantPolicy = {
  version: "oaath.grant-policy/v1",
  calls: [
    {
      target: firstTarget,
      selector: firstSelector,
      valueLimit: "100",
      argumentEquals: [
        { index: 0, value: firstWord },
        { index: 2, value: secondWord },
      ],
    },
    {
      target: secondTarget,
      selector: secondSelector,
      valueLimit: "0",
      argumentEquals: [],
    },
  ],
  validAfter: 100,
  validUntil: 200,
  perChainOperationLimit: 2,
};

function callAt(value: GrantPolicy, index: number) {
  const call = value.calls[index];
  if (!call) throw new Error(`missing policy call ${index}`);
  return call;
}

const firstPolicyCall = callAt(policy, 0);
const secondPolicyCall = callAt(policy, 1);

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function calldata(selector: `0x${string}`, words: readonly `0x${string}`[] = []): `0x${string}` {
  return `0x${selector.slice(2)}${words.map((entry) => entry.slice(2)).join("")}`;
}

function completeUsage(chainId = 1, count = "0", grantId = "grant-policy-test") {
  return {
    version: OAATH_GRANT_POLICY_USAGE_VERSION,
    status: "complete" as const,
    grantId,
    chainId,
    finalizedOperationCount: count,
    through: {
      blockNumber: "50",
      blockHash: `0x${"66".repeat(32)}` as const,
      observedAt: 150,
    },
  };
}

function coverageInput(
  overrides: Partial<GrantPolicyCoverageInput> = {},
): GrantPolicyCoverageInput {
  return {
    policy,
    grantId: "grant-policy-test",
    chainId: 1,
    evaluatedAt: 150,
    calls: [
      {
        target: firstTarget,
        data: calldata(firstSelector, [firstWord, fillerWord, secondWord]),
        value: "100",
      },
    ],
    usage: completeUsage(),
    ...overrides,
  };
}

function expectPolicyError(action: () => unknown, code: OaathGrantPolicyError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathGrantPolicyError);
    expect(error).toMatchObject({ code });
    return;
  }
  throw new Error(`Expected ${code}`);
}

describe("canonical Grant policy", () => {
  it("round-trips one immutable current policy with a stable domain-separated encoding", () => {
    expect(OAATH_GRANT_POLICY_VERSION).toBe("oaath.grant-policy/v1");
    expect(OAATH_GRANT_POLICY_HASH_DOMAIN).toBe("@oaath/protocol:grant-policy");
    const mutable = clone(policy);
    const parsed = parseGrantPolicy(mutable);
    (mutable.calls[0] as { valueLimit: string }).valueLimit = "999";

    expect(parsed).toEqual(policy);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.calls)).toBe(true);
    expect(Object.isFrozen(parsed.calls[0])).toBe(true);
    expect(Object.isFrozen(parsed.calls[0]?.argumentEquals)).toBe(true);
    expect(parseGrantPolicy(clone(parsed))).toEqual(parsed);
    expect(encodeGrantPolicy(clone(parsed))).toBe(encodeGrantPolicy(parsed));
    expect(hashGrantPolicy(clone(parsed))).toBe(hashGrantPolicy(parsed));
    expect(encodeGrantPolicy(parsed)).toMatch(/^0x[0-9a-f]+$/u);
    expect(hashGrantPolicy(parsed)).toBe(
      "0xd6cb7a93913679feb6451b65a20d18b1e9a9c0c16acbc466e6a04dc29b6459ce",
    );

    const indefinite = { ...clone(policy), validUntil: null };
    expect(hashGrantPolicy(indefinite)).not.toBe(hashGrantPolicy(policy));
    expect(parseGrantPolicy({ ...clone(policy), validAfter: 1, validUntil: 1 })).toMatchObject({
      validAfter: 1,
      validUntil: 1,
    });
  });

  it("owns only fixed ABI-word equality and contains no chain inventory or policy DSL", () => {
    const keys = new Set<string>();
    const collect = (value: unknown): void => {
      if (value === null || typeof value !== "object") return;
      for (const [key, child] of Object.entries(value)) {
        keys.add(key.toLowerCase());
        collect(child);
      }
    };
    collect(parseGrantPolicy(policy));
    for (const forbidden of [
      "chainid",
      "chainids",
      "chains",
      "supportedchains",
      "globaloperationlimit",
      "condition",
      "comparator",
      "calltype",
      "policyaddress",
      "default",
      "fallback",
    ]) {
      expect(keys.has(forbidden), `forbidden policy key: ${forbidden}`).toBe(false);
    }
  });

  it("rejects aliases, malformed encodings, overflow, duplicates, and noncanonical order", () => {
    const maxUint256 = (1n << 256n) - 1n;
    const invalidPolicies: unknown[] = [
      { ...clone(policy), version: "oaath.grant-policy/v0" },
      { ...clone(policy), extra: true },
      { ...clone(policy), calls: [] },
      { ...clone(policy), validAfter: -0 },
      { ...clone(policy), validAfter: 1.5 },
      { ...clone(policy), validAfter: 2 ** 48 },
      { ...clone(policy), validUntil: 0 },
      { ...clone(policy), validUntil: 99 },
      { ...clone(policy), validUntil: undefined },
      { ...clone(policy), perChainOperationLimit: 0 },
      { ...clone(policy), perChainOperationLimit: 2 ** 48 },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), target: firstTarget.toUpperCase() }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), target: `0x${"00".repeat(20)}` }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), selector: "0x00000000" }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), selector: "0x1234" }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), valueLimit: "01" }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), valueLimit: `0x${maxUint256.toString(16)}` }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), valueLimit: (maxUint256 + 1n).toString() }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), argumentEquals: [{ index: -0, value: firstWord }] }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), argumentEquals: [{ index: 0.5, value: firstWord }] }],
      },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), argumentEquals: [{ index: 0, value: "0x12" }] }],
      },
      {
        ...clone(policy),
        calls: [
          {
            ...clone(firstPolicyCall),
            argumentEquals: [
              { index: 0, value: firstWord },
              { index: 0, value: secondWord },
            ],
          },
        ],
      },
      {
        ...clone(policy),
        calls: [
          {
            ...clone(firstPolicyCall),
            argumentEquals: [
              { index: 2, value: secondWord },
              { index: 0, value: firstWord },
            ],
          },
        ],
      },
      { ...clone(policy), calls: [...clone(policy.calls)].reverse() },
      { ...clone(policy), calls: [clone(firstPolicyCall), clone(firstPolicyCall)] },
      {
        ...clone(policy),
        calls: [{ ...clone(firstPolicyCall), argumentEquals: new Uint8Array(32) }],
      },
    ];
    for (const value of invalidPolicies) {
      expectPolicyError(() => parseGrantPolicy(value), "grant_policy_invalid");
    }
  });

  it("rejects sparse, accessor, symbol, proxy, and caller-aliased inputs with a stable code", () => {
    const sparse = clone(policy) as unknown as { calls: unknown[] };
    sparse.calls.length += 1;
    const accessor = clone(policy) as unknown as Record<string, unknown>;
    Object.defineProperty(accessor, "validAfter", { enumerable: true, get: () => 100 });
    const symbol = { ...clone(policy), [Symbol("hidden")]: true };
    const shared = { index: 0, value: firstWord };
    const aliased = {
      ...clone(policy),
      calls: [
        {
          ...clone(firstPolicyCall),
          argumentEquals: [shared, shared],
        },
      ],
    };
    const proxy = new Proxy(clone(policy), {
      getOwnPropertyDescriptor() {
        throw new Error("hostile proxy");
      },
    });

    for (const value of [sparse, accessor, symbol, aliased, proxy]) {
      expectPolicyError(() => parseGrantPolicy(value), "grant_policy_invalid");
    }
  });
});

describe("Grant policy attenuation", () => {
  it("accepts removal and narrowing, including added equality constraints", () => {
    const approved: GrantPolicy = {
      ...clone(policy),
      calls: [
        {
          ...clone(firstPolicyCall),
          valueLimit: "50",
          argumentEquals: [
            { index: 0, value: firstWord },
            { index: 1, value: fillerWord },
            { index: 2, value: secondWord },
          ],
        },
      ],
      validAfter: 110,
      validUntil: 190,
      perChainOperationLimit: 1,
    };
    expect(isGrantPolicyAttenuation(policy, policy)).toBe(true);
    expect(isGrantPolicyAttenuation(policy, approved)).toBe(true);
  });

  it("rejects every widening dimension and never merges separate parent alternatives", () => {
    const first = clone(firstPolicyCall);
    const widenings: GrantPolicy[] = [
      { ...clone(policy), validAfter: 99 },
      { ...clone(policy), validUntil: 201 },
      { ...clone(policy), validUntil: null },
      { ...clone(policy), perChainOperationLimit: 3 },
      {
        ...clone(policy),
        calls: [{ ...first, valueLimit: "101" }, clone(secondPolicyCall)],
      },
      {
        ...clone(policy),
        calls: [
          { ...first, argumentEquals: [{ index: 0, value: firstWord }] },
          clone(secondPolicyCall),
        ],
      },
      {
        ...clone(policy),
        calls: [
          { ...first, argumentEquals: [{ index: 0, value: secondWord }] },
          clone(secondPolicyCall),
        ],
      },
      {
        ...clone(policy),
        calls: [
          clone(firstPolicyCall),
          clone(secondPolicyCall),
          {
            target: `0x${"33".repeat(20)}`,
            selector: "0x11111111",
            valueLimit: "0",
            argumentEquals: [],
          },
        ],
      },
    ];
    for (const approved of widenings) {
      expect(isGrantPolicyAttenuation(policy, approved)).toBe(false);
    }
  });

  it("rejects hostile attenuation inputs under the attenuation boundary code", () => {
    expectPolicyError(
      () => isGrantPolicyAttenuation(policy, { ...clone(policy), validAfter: -0 }),
      "grant_policy_attenuation_input_invalid",
    );
  });
});

describe("Grant policy coverage", () => {
  it("covers inclusive endpoints and a complete batch as one chain-local use", () => {
    const calls = [
      ...coverageInput().calls,
      { target: secondTarget, data: calldata(secondSelector), value: "0" as const },
      { target: secondTarget, data: calldata(secondSelector), value: "0" as const },
    ];
    for (const evaluatedAt of [100, 200]) {
      expect(evaluateGrantPolicyCoverage(coverageInput({ calls, evaluatedAt }))).toEqual({
        status: "covered",
        policyHash: hashGrantPolicy(policy),
        chainId: 1,
        finalizedOperationCount: "0",
        uses: 1,
      });
    }
  });

  it("denies target, selector, argument, value, time, empty-batch, and count substitutions", () => {
    const baseCall = coverageInput().calls[0];
    if (!baseCall) throw new Error("missing fixture call");
    const cases: readonly [Partial<GrantPolicyCoverageInput>, string, number | null][] = [
      [{ calls: [] }, "empty_calls", null],
      [{ evaluatedAt: 99 }, "outside_time_window", null],
      [{ evaluatedAt: 201 }, "outside_time_window", null],
      [{ calls: [{ ...baseCall, target: secondTarget }] }, "call_not_permitted", 0],
      [
        { calls: [{ ...baseCall, data: calldata("0x87654321", [firstWord]) }] },
        "call_not_permitted",
        0,
      ],
      [
        {
          calls: [
            {
              ...baseCall,
              data: calldata(firstSelector, [secondWord, fillerWord, secondWord]),
            },
          ],
        },
        "argument_not_permitted",
        0,
      ],
      [
        { calls: [{ ...baseCall, data: calldata(firstSelector, [firstWord]) }] },
        "argument_not_permitted",
        0,
      ],
      [{ calls: [{ ...baseCall, value: "101" }] }, "value_limit_exceeded", 0],
      [{ usage: completeUsage(1, "2") }, "operation_limit_exhausted", null],
    ];
    for (const [overrides, reason, callIndex] of cases) {
      expect(evaluateGrantPolicyCoverage(coverageInput(overrides))).toMatchObject({
        status: "denied",
        reason,
        callIndex,
      });
    }
  });

  it("never turns missing, unreadable, unresolved, or cross-chain evidence into allowance", () => {
    const cases: readonly [GrantPolicyCoverageInput["usage"], string][] = [
      [null, "usage_missing"],
      [
        {
          version: OAATH_GRANT_POLICY_USAGE_VERSION,
          status: "unavailable",
          reason: "unreadable",
        },
        "usage_unreadable",
      ],
      [
        {
          version: OAATH_GRANT_POLICY_USAGE_VERSION,
          status: "unavailable",
          reason: "non_finalized",
        },
        "usage_non_finalized",
      ],
      [
        {
          version: OAATH_GRANT_POLICY_USAGE_VERSION,
          status: "unavailable",
          reason: "canonicality_unproven",
        },
        "usage_canonicality_unproven",
      ],
      [completeUsage(2), "usage_identity_mismatch"],
      [completeUsage(1, "0", "another-grant"), "usage_identity_mismatch"],
    ];
    for (const [usage, reason] of cases) {
      expect(evaluateGrantPolicyCoverage(coverageInput({ usage }))).toMatchObject({
        status: "inconclusive",
        reason,
      });
    }
  });

  it("counts finalized reverted executions as consumed and rejects operation-shaped evidence", () => {
    expect(
      evaluateGrantPolicyCoverage(coverageInput({ usage: completeUsage(1, "1") })),
    ).toMatchObject({ status: "covered", finalizedOperationCount: "1", uses: 1 });
    expect(
      evaluateGrantPolicyCoverage(coverageInput({ usage: completeUsage(1, "2") })),
    ).toMatchObject({ status: "denied", reason: "operation_limit_exhausted" });

    expectPolicyError(
      () =>
        evaluateGrantPolicyCoverage(
          coverageInput({
            usage: {
              version: OAATH_GRANT_POLICY_USAGE_VERSION,
              status: "complete",
              grantId: "grant-policy-test",
              chainId: 1,
              finalizedOperationCount: "0",
              through: completeUsage().through,
              outcome: "reverted",
            } as never,
          }),
        ),
      "grant_policy_coverage_input_invalid",
    );
  });

  it("rejects malformed call and usage evidence under one stable boundary code", () => {
    const call = coverageInput().calls[0];
    if (!call) throw new Error("missing fixture call");
    const invalidInputs: unknown[] = [
      { ...coverageInput(), extra: true },
      { ...coverageInput(), chainId: 0 },
      { ...coverageInput(), evaluatedAt: -0 },
      { ...coverageInput(), calls: [{ ...call, data: "0x123" }] },
      { ...coverageInput(), calls: [{ ...call, data: call.data.toUpperCase() }] },
      { ...coverageInput(), calls: [{ ...call, value: "01" }] },
      { ...coverageInput(), usage: { ...completeUsage(), finalizedOperationCount: "01" } },
      { ...coverageInput(), usage: { ...completeUsage(), through: { blockNumber: "1" } } },
      {
        ...coverageInput(),
        usage: {
          version: OAATH_GRANT_POLICY_USAGE_VERSION,
          status: "unavailable",
          reason: "reverted",
        },
      },
    ];
    for (const value of invalidInputs) {
      expectPolicyError(
        () => evaluateGrantPolicyCoverage(value),
        "grant_policy_coverage_input_invalid",
      );
    }
  });
});

describe("Grant policy properties", () => {
  it("keeps canonical parse/encode/hash deterministic across JSON recreation", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 1_000_000 }),
        fc.integer({ min: 0, max: 1_000_000 }),
        fc.integer({ min: 1, max: 1_000 }),
        fc.bigInt({ min: 0n, max: 1n << 128n }),
        (start, duration, limit, valueLimit) => {
          fc.pre(start !== 0 || duration !== 0);
          const generated: GrantPolicy = {
            version: OAATH_GRANT_POLICY_VERSION,
            calls: [
              {
                target: firstTarget,
                selector: firstSelector,
                valueLimit: valueLimit.toString(),
                argumentEquals: [{ index: 0, value: firstWord }],
              },
            ],
            validAfter: start,
            validUntil: start + duration,
            perChainOperationLimit: limit,
          };
          const restored = parseGrantPolicy(clone(generated));
          expect(restored).toEqual(generated);
          expect(encodeGrantPolicy(restored)).toBe(encodeGrantPolicy(generated));
          expect(hashGrantPolicy(restored)).toBe(hashGrantPolicy(generated));
        },
      ),
    );
  });

  it("proves generated narrowing is monotonic", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 1_000 }),
        fc.integer({ min: 0, max: 1_000 }),
        fc.integer({ min: 1, max: 1_000 }),
        fc.integer({ min: 1, max: 1_000 }),
        (start, duration, requestedLimit, requestedValue) => {
          fc.pre(start !== 0 || duration !== 0);
          const requested: GrantPolicy = {
            version: OAATH_GRANT_POLICY_VERSION,
            calls: [
              {
                target: firstTarget,
                selector: firstSelector,
                valueLimit: String(requestedValue),
                argumentEquals: [{ index: 0, value: firstWord }],
              },
            ],
            validAfter: start,
            validUntil: start + duration,
            perChainOperationLimit: requestedLimit,
          };
          const approved: GrantPolicy = {
            ...clone(requested),
            calls: [
              {
                ...clone(callAt(requested, 0)),
                valueLimit: String(Math.floor(requestedValue / 2)),
                argumentEquals: [
                  { index: 0, value: firstWord },
                  { index: 1, value: secondWord },
                ],
              },
            ],
            validAfter: start + Math.floor(duration / 2),
            validUntil: start + duration,
            perChainOperationLimit: Math.max(1, Math.floor(requestedLimit / 2)),
          };
          expect(isGrantPolicyAttenuation(requested, approved)).toBe(true);
          expect(
            isGrantPolicyAttenuation(approved, {
              ...clone(approved),
              perChainOperationLimit: requestedLimit + 1,
            }),
          ).toBe(false);
        },
      ),
    );
  });

  it("never borrows a complete count from an arbitrary other chain", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 1_000_000 }),
        fc.integer({ min: 1, max: 1_000_000 }),
        fc.integer({ min: 0, max: 10 }),
        (chainId, delta, count) => {
          const otherChainId = chainId + delta;
          fc.pre(otherChainId !== chainId);
          expect(
            evaluateGrantPolicyCoverage(
              coverageInput({ chainId, usage: completeUsage(otherChainId, String(count)) }),
            ),
          ).toMatchObject({ status: "inconclusive", reason: "usage_identity_mismatch" });
        },
      ),
    );
  });
});
