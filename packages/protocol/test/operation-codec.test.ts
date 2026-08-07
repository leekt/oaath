import { describe, expect, it } from "vitest";
import {
  advanceOperation,
  createOperation,
  OaathOperationError,
  type OperationIdentity,
  parseOperation,
} from "../src/index.js";
import { applyVerifiedOperationObservation } from "../src/operation.js";

const identity: OperationIdentity = {
  kind: "revocation",
  grantId: "grant-codec",
  chainId: 1,
  entryPoint: `0x${"11".repeat(20)}`,
  account: `0x${"22".repeat(20)}`,
  nonce: "0",
  userOperationHash: `0x${"33".repeat(32)}`,
  requestHash: null,
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectOperationError(action: () => unknown, code: OaathOperationError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathOperationError);
    expect((error as OaathOperationError).code).toBe(code);
    return;
  }
  throw new Error(`Expected ${code}`);
}

function expectRecordInvalid(value: unknown): void {
  expectOperationError(() => parseOperation(value), "operation_record_invalid");
}

function replacementDrop(observedAt = 13) {
  return {
    kind: "finalized_nonce_replacement" as const,
    replacement: {
      identity: {
        chainId: identity.chainId,
        entryPoint: identity.entryPoint,
        account: identity.account,
        nonce: identity.nonce,
        userOperationHash: `0x${"77".repeat(32)}` as const,
      },
      inclusion: {
        transactionHash: `0x${"44".repeat(32)}` as const,
        blockNumber: "30",
        blockHash: `0x${"55".repeat(32)}` as const,
        outcome: "success" as const,
        observedAt: observedAt - 1,
      },
      finality: {
        blockNumber: "35",
        blockHash: `0x${"66".repeat(32)}` as const,
        observedAt,
      },
    },
  };
}

function abandonedOperation() {
  return advanceOperation(createOperation({ identity, preparedAt: 10 }), {
    type: "mark_abandoned",
    identity,
    abandonedAt: 11,
    reason: "submission_not_attempted",
  });
}

describe("Operation current codec", () => {
  it("round-trips the one current JSON-safe record", () => {
    const operation = advanceOperation(createOperation({ identity, preparedAt: 10 }), {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    const restored = parseOperation(clone(operation));
    expect(restored).toEqual(operation);
    expect(Object.isFrozen(restored)).toBe(true);
    expect(Object.isFrozen(restored.identity)).toBe(true);
    expect(restored.identity.requestHash).toBeNull();
  });

  it("round-trips, validates, and freezes provider request provenance", () => {
    const requestHash = `0x${"aa".repeat(32)}` as const;
    const operation = createOperation({
      identity: { ...identity, requestHash },
      preparedAt: 10,
    });
    const restored = parseOperation(clone(operation));

    expect(restored.identity.requestHash).toBe(requestHash);
    expect(Object.isFrozen(restored.identity)).toBe(true);
    expect(Reflect.set(restored.identity, "requestHash", null)).toBe(false);
    expect(restored.identity.requestHash).toBe(requestHash);

    for (const invalidRequestHash of ["0x1234", `0x${"AA".repeat(32)}`, undefined]) {
      expectOperationError(
        () =>
          createOperation({
            identity: { ...identity, requestHash: invalidRequestHash },
            preparedAt: 10,
          }),
        "operation_input_invalid",
      );
    }

    const missingRequestHash = { ...identity } as Record<string, unknown>;
    delete missingRequestHash.requestHash;
    expectOperationError(
      () => createOperation({ identity: missingRequestHash, preparedAt: 10 }),
      "operation_input_invalid",
    );
  });

  it("accepts only the exact current abandoned record", () => {
    const operation = abandonedOperation();
    expect(parseOperation(clone(operation))).toEqual(operation);

    for (const invalid of [
      { ...operation, version: "oaath.operation/v0" },
      { ...operation, state: "expired" },
      { ...operation, revision: 0 },
      { ...operation, revision: 2 },
      { ...operation, abandonedAt: 9, updatedAt: 9 },
      { ...operation, updatedAt: 12 },
      {
        ...operation,
        identity: { ...operation.identity, userOperationHash: "0x1234" },
      },
      { ...operation, abandonment: { reason: "provider_unavailable" } },
      {
        ...operation,
        abandonment: { reason: "submission_not_attempted", provider: "forbidden" },
      },
      {
        ...operation,
        observation: { status: "pending", observedAt: 12, reason: "receipt_missing" },
      },
      { ...operation, legacyState: "cancelled" },
    ]) {
      expectRecordInvalid(invalid);
    }
  });

  it("rejects wrong versions, extra fields, missing fields, and symbols", () => {
    const operation = clone(createOperation({ identity, preparedAt: 10 })) as unknown as Record<
      PropertyKey,
      unknown
    >;

    expectRecordInvalid({ ...operation, version: "oaath.operation/v0" });
    expectRecordInvalid({ ...operation, version: "oaath.operation/v1" });
    expectRecordInvalid({ ...operation, compatibilityState: "legacy" });

    const missing = { ...operation };
    delete missing.updatedAt;
    expectRecordInvalid(missing);

    const symbol = { ...operation, [Symbol("hidden")]: true };
    expectRecordInvalid(symbol);

    const nonEnumerable = { ...operation };
    Object.defineProperty(nonEnumerable, "hidden", { enumerable: false, value: true });
    expectRecordInvalid(nonEnumerable);
  });

  it("rejects accessors without invoking them", () => {
    let calls = 0;
    const hostileIdentity: Record<string, unknown> = {
      kind: identity.kind,
      grantId: identity.grantId,
      chainId: identity.chainId,
      entryPoint: identity.entryPoint,
      account: identity.account,
      nonce: identity.nonce,
      requestHash: identity.requestHash,
    };
    Object.defineProperty(hostileIdentity, "userOperationHash", {
      enumerable: true,
      get() {
        calls += 1;
        return identity.userOperationHash;
      },
    });

    expectOperationError(
      () => createOperation({ identity: hostileIdentity, preparedAt: 10 }),
      "operation_input_invalid",
    );
    expect(calls).toBe(0);
  });

  it("rejects non-plain prototypes and canonical scalar aliases", () => {
    class HostileRecord {
      identity = identity;
      preparedAt = 10;
    }
    expectOperationError(() => createOperation(new HostileRecord()), "operation_input_invalid");

    expectOperationError(
      () =>
        createOperation({
          identity: { ...identity, account: identity.account.toUpperCase() },
          preparedAt: 10,
        }),
      "operation_input_invalid",
    );
    expectOperationError(
      () => createOperation({ identity: { ...identity, nonce: "00" }, preparedAt: 10 }),
      "operation_input_invalid",
    );
    expectOperationError(
      () => createOperation({ identity: { ...identity, chainId: 0 }, preparedAt: 10 }),
      "operation_input_invalid",
    );
    expectOperationError(
      () => createOperation({ identity, preparedAt: -0 }),
      "operation_input_invalid",
    );
    expectOperationError(
      () =>
        createOperation({
          identity: { ...identity, account: `0x${"00".repeat(20)}` },
          preparedAt: 10,
        }),
      "operation_input_invalid",
    );
  });

  it("rejects state contradictions and malformed evidence", () => {
    const attempted = advanceOperation(createOperation({ identity, preparedAt: 10 }), {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    expectRecordInvalid({ ...attempted, updatedAt: 9 });
    expectRecordInvalid({
      ...attempted,
      observation: { status: "pending", observedAt: 12, reason: "maybe" },
    });
    expectRecordInvalid({ ...attempted, state: "submitted" });

    const submitted = advanceOperation(attempted, {
      type: "mark_submitted",
      identity,
      returnedUserOperationHash: identity.userOperationHash,
      submittedAt: 12,
    });
    expectRecordInvalid({ ...submitted, submittedAt: 10 });
    expectRecordInvalid({ ...submitted, inclusion: null });
  });

  it("rejects hostile transition accessors without invoking them", () => {
    const operation = createOperation({ identity, preparedAt: 10 });
    let calls = 0;
    const transition: Record<string, unknown> = {
      type: "mark_submission_attempted",
      identity,
    };
    Object.defineProperty(transition, "attemptedAt", {
      enumerable: true,
      get() {
        calls += 1;
        return 11;
      },
    });
    expectOperationError(
      () => advanceOperation(operation, transition),
      "operation_transition_invalid",
    );
    expect(calls).toBe(0);
  });

  it("rejects an accessor-backed abandonment reason without invoking it", () => {
    const operation = createOperation({ identity, preparedAt: 10 });
    let calls = 0;
    const transition: Record<string, unknown> = {
      type: "mark_abandoned",
      identity,
      abandonedAt: 11,
    };
    Object.defineProperty(transition, "reason", {
      enumerable: true,
      get() {
        calls += 1;
        return "submission_not_attempted";
      },
    });
    expectOperationError(
      () => advanceOperation(operation, transition),
      "operation_transition_invalid",
    );
    expect(calls).toBe(0);
  });

  it("rejects aliased nested records and unstable proxy discriminants", () => {
    const attempted = clone(
      advanceOperation(createOperation({ identity, preparedAt: 10 }), {
        type: "mark_submission_attempted",
        identity,
        attemptedAt: 11,
      }),
    ) as unknown as Record<string, unknown>;
    attempted.observation = attempted.identity;
    expectRecordInvalid(attempted);

    let stateReads = 0;
    const source = clone(createOperation({ identity, preparedAt: 10 }));
    const unstable = new Proxy(source, {
      getOwnPropertyDescriptor(target, key) {
        const descriptor = Reflect.getOwnPropertyDescriptor(target, key);
        if (key === "state" && descriptor && "value" in descriptor) {
          stateReads += 1;
          return { ...descriptor, value: stateReads === 1 ? "prepared" : "included" };
        }
        return descriptor;
      },
    });
    expect(parseOperation(unstable)).toEqual(source);
    expect(stateReads).toBe(1);

    const targetIncluded = applyVerifiedOperationObservation(
      advanceOperation(createOperation({ identity, preparedAt: 10 }), {
        type: "mark_submission_attempted",
        identity,
        attemptedAt: 11,
      }),
      {
        type: "record_included",
        identity,
        inclusion: {
          transactionHash: `0x${"aa".repeat(32)}`,
          blockNumber: "20",
          blockHash: `0x${"bb".repeat(32)}`,
          outcome: "success",
          observedAt: 12,
        },
      },
    );
    const dropped = applyVerifiedOperationObservation(targetIncluded, {
      type: "record_dropped",
      identity,
      drop: replacementDrop(15),
    });
    type MutableDroppedRecord = {
      priorInclusion: Record<string, unknown>;
      drop: { replacement: { inclusion: Record<string, unknown> } };
    };

    const aliased = clone(dropped) as unknown as MutableDroppedRecord;
    aliased.drop.replacement.inclusion = aliased.priorInclusion;
    expectRecordInvalid(aliased);

    const copied = clone(dropped) as unknown as MutableDroppedRecord;
    copied.drop.replacement.inclusion = { ...copied.priorInclusion, outcome: "reverted" };
    expectRecordInvalid(copied);

    if (targetIncluded.state !== "included") throw new Error("Expected included operation");
    const transitionDrop = replacementDrop(15);
    expectOperationError(
      () =>
        applyVerifiedOperationObservation(targetIncluded, {
          type: "record_dropped",
          identity,
          drop: {
            ...transitionDrop,
            replacement: {
              ...transitionDrop.replacement,
              inclusion: { ...targetIncluded.inclusion, outcome: "reverted" },
            },
          },
        }),
      "operation_transition_invalid",
    );
  });

  it("sanitizes hostile reflection failures", () => {
    const secret = "do-not-leak-this-provider-secret";
    function hostile(code: OaathOperationError["code"]): object {
      return new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new OaathOperationError(code, secret);
          },
        },
      );
    }

    const actions: Array<readonly [() => unknown, OaathOperationError["code"]]> = [
      [() => parseOperation(hostile("operation_record_invalid")), "operation_record_invalid"],
      [() => createOperation(hostile("operation_input_invalid")), "operation_input_invalid"],
      [
        () =>
          advanceOperation(
            createOperation({ identity, preparedAt: 10 }),
            hostile("operation_transition_invalid"),
          ),
        "operation_transition_invalid",
      ],
    ];
    for (const [action, code] of actions) {
      try {
        action();
      } catch (error) {
        expect(error).toBeInstanceOf(OaathOperationError);
        expect((error as OaathOperationError).code).toBe(code);
        expect((error as Error).message).not.toContain(secret);
        continue;
      }
      throw new Error(`Expected ${code}`);
    }

    const secretField = clone(createOperation({ identity, preparedAt: 10 }));
    Object.defineProperty(secretField, secret, { enumerable: false, value: true });
    try {
      parseOperation(secretField);
    } catch (error) {
      expect((error as Error).message).not.toContain(secret);
      return;
    }
    throw new Error("Expected hostile property name to reject");
  });

  it("requires a distinct finalized same-lane replacement to record dropped", () => {
    const attempted = advanceOperation(createOperation({ identity, preparedAt: 10 }), {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    const validDrop = replacementDrop();
    const drop = {
      ...validDrop,
      replacement: {
        ...validDrop.replacement,
        identity: {
          ...validDrop.replacement.identity,
          userOperationHash: identity.userOperationHash,
        },
      },
    };
    expectOperationError(
      () =>
        applyVerifiedOperationObservation(attempted, { type: "record_dropped", identity, drop }),
      "operation_transition_invalid",
    );

    expectOperationError(
      () =>
        applyVerifiedOperationObservation(attempted, {
          type: "record_dropped",
          identity,
          drop: {
            ...drop,
            replacement: {
              ...drop.replacement,
              identity: {
                ...drop.replacement.identity,
                nonce: "1",
                userOperationHash: `0x${"77".repeat(32)}`,
              },
            },
          },
        }),
      "operation_transition_invalid",
    );
  });

  it("rejects a same-height finality block that contradicts inclusion", () => {
    const attempted = advanceOperation(createOperation({ identity, preparedAt: 10 }), {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    const included = applyVerifiedOperationObservation(attempted, {
      type: "record_included",
      identity,
      inclusion: {
        transactionHash: `0x${"44".repeat(32)}`,
        blockNumber: "20",
        blockHash: `0x${"55".repeat(32)}`,
        outcome: "success",
        observedAt: 12,
      },
    });
    expectOperationError(
      () =>
        applyVerifiedOperationObservation(included, {
          type: "record_finalized",
          identity,
          finality: {
            blockNumber: "20",
            blockHash: `0x${"66".repeat(32)}`,
            observedAt: 13,
          },
        }),
      "operation_transition_invalid",
    );
  });

  it("rejects revision exhaustion before producing an unsafe alias", () => {
    const prepared = createOperation({ identity, preparedAt: 10 });
    expectRecordInvalid({ ...prepared, revision: 1 });
    expectRecordInvalid({ ...prepared, revision: 999 });

    const abandoned = abandonedOperation();
    expectRecordInvalid({ ...abandoned, revision: 0 });
    expectRecordInvalid({ ...abandoned, revision: 2 });

    const attempted = advanceOperation(prepared, {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    expectRecordInvalid({ ...attempted, revision: 0 });
    expectRecordInvalid({ ...attempted, revision: 2 });

    const observedAttempt = applyVerifiedOperationObservation(attempted, {
      type: "record_pending",
      identity,
      observedAt: 12,
      reason: "timeout",
    });
    expectRecordInvalid({ ...observedAttempt, revision: 1 });

    const submitted = advanceOperation(attempted, {
      type: "mark_submitted",
      identity,
      returnedUserOperationHash: identity.userOperationHash,
      submittedAt: 12,
    });
    expectRecordInvalid({ ...submitted, revision: 1 });
    const observedSubmitted = applyVerifiedOperationObservation(submitted, {
      type: "record_pending",
      identity,
      observedAt: 13,
      reason: "timeout",
    });
    expectRecordInvalid({ ...observedSubmitted, revision: 2 });

    const included = applyVerifiedOperationObservation(submitted, {
      type: "record_included",
      identity,
      inclusion: {
        transactionHash: `0x${"44".repeat(32)}`,
        blockNumber: "20",
        blockHash: `0x${"55".repeat(32)}`,
        outcome: "success",
        observedAt: 13,
      },
    });
    expectRecordInvalid({ ...included, revision: 2 });
    const observedIncluded = applyVerifiedOperationObservation(included, {
      type: "record_unreadable",
      identity,
      observedAt: 14,
      reason: "provider_unavailable",
    });
    expectRecordInvalid({ ...observedIncluded, revision: 3 });

    const finalized = applyVerifiedOperationObservation(included, {
      type: "record_finalized",
      identity,
      finality: {
        blockNumber: "25",
        blockHash: `0x${"66".repeat(32)}`,
        observedAt: 14,
      },
    });
    expectRecordInvalid({ ...finalized, revision: 3 });

    const droppedAfterSubmitted = applyVerifiedOperationObservation(submitted, {
      type: "record_dropped",
      identity,
      drop: replacementDrop(15),
    });
    expectRecordInvalid({ ...droppedAfterSubmitted, revision: 2 });

    const droppedAfterIncluded = applyVerifiedOperationObservation(included, {
      type: "record_dropped",
      identity,
      drop: replacementDrop(15),
    });
    expectRecordInvalid({ ...droppedAfterIncluded, revision: 3 });

    const exhausted = {
      ...observedAttempt,
      revision: Number.MAX_SAFE_INTEGER,
    };
    expectOperationError(
      () =>
        applyVerifiedOperationObservation(exhausted, {
          type: "record_pending",
          identity,
          observedAt: 13,
          reason: "timeout",
        }),
      "operation_revision_exhausted",
    );
  });
});
