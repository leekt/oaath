import { describe, expect, it } from "vitest";
import {
  advanceOperation,
  createOperation,
  OgpOperationError,
  type OperationIdentity,
  parseOperation,
} from "../src/index.js";

const identity: OperationIdentity = {
  kind: "revocation",
  grantId: "grant-codec",
  chainId: 1,
  entryPoint: `0x${"11".repeat(20)}`,
  account: `0x${"22".repeat(20)}`,
  nonce: "0",
  userOperationHash: `0x${"33".repeat(32)}`,
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectOperationError(action: () => unknown, code: OgpOperationError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OgpOperationError);
    expect((error as OgpOperationError).code).toBe(code);
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
  });

  it("rejects wrong versions, extra fields, missing fields, and symbols", () => {
    const operation = clone(createOperation({ identity, preparedAt: 10 })) as unknown as Record<
      PropertyKey,
      unknown
    >;

    expectRecordInvalid({ ...operation, version: "ogp.operation/v0" });
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
  });

  it("sanitizes hostile reflection failures", () => {
    const secret = "do-not-leak-this-provider-secret";
    function hostile(code: OgpOperationError["code"]): object {
      return new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new OgpOperationError(code, secret);
          },
        },
      );
    }

    const actions: Array<readonly [() => unknown, OgpOperationError["code"]]> = [
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
        expect(error).toBeInstanceOf(OgpOperationError);
        expect((error as OgpOperationError).code).toBe(code);
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
      () => advanceOperation(attempted, { type: "record_dropped", identity, drop }),
      "operation_transition_invalid",
    );

    expectOperationError(
      () =>
        advanceOperation(attempted, {
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
    const included = advanceOperation(attempted, {
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
        advanceOperation(included, {
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

    const attempted = advanceOperation(prepared, {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    expectRecordInvalid({ ...attempted, revision: 0 });
    expectRecordInvalid({ ...attempted, revision: 2 });

    const observedAttempt = advanceOperation(attempted, {
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
    const observedSubmitted = advanceOperation(submitted, {
      type: "record_pending",
      identity,
      observedAt: 13,
      reason: "timeout",
    });
    expectRecordInvalid({ ...observedSubmitted, revision: 2 });

    const included = advanceOperation(submitted, {
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
    const observedIncluded = advanceOperation(included, {
      type: "record_unreadable",
      identity,
      observedAt: 14,
      reason: "provider_unavailable",
    });
    expectRecordInvalid({ ...observedIncluded, revision: 3 });

    const finalized = advanceOperation(included, {
      type: "record_finalized",
      identity,
      finality: {
        blockNumber: "25",
        blockHash: `0x${"66".repeat(32)}`,
        observedAt: 14,
      },
    });
    expectRecordInvalid({ ...finalized, revision: 3 });

    const droppedAfterSubmitted = advanceOperation(submitted, {
      type: "record_dropped",
      identity,
      drop: replacementDrop(15),
    });
    expectRecordInvalid({ ...droppedAfterSubmitted, revision: 2 });

    const droppedAfterIncluded = advanceOperation(included, {
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
        advanceOperation(exhausted, {
          type: "record_pending",
          identity,
          observedAt: 13,
          reason: "timeout",
        }),
      "operation_revision_exhausted",
    );
  });
});
