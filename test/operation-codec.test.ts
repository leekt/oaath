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
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error("do-not-leak-this-provider-secret");
        },
      },
    );
    try {
      parseOperation(hostile);
    } catch (error) {
      expect(error).toBeInstanceOf(OgpOperationError);
      expect((error as OgpOperationError).code).toBe("operation_record_invalid");
      expect((error as Error).message).not.toContain("do-not-leak");
      return;
    }
    throw new Error("Expected hostile reflection to reject");
  });

  it("requires a positive same-lane nonce advance to record dropped", () => {
    const attempted = advanceOperation(createOperation({ identity, preparedAt: 10 }), {
      type: "mark_submission_attempted",
      identity,
      attemptedAt: 11,
    });
    const drop = {
      kind: "finalized_nonce_replacement" as const,
      observedNonce: "0",
      finalizedBlockNumber: "30",
      finalizedBlockHash: `0x${"44".repeat(32)}` as const,
      observedAt: 12,
    };
    expectOperationError(
      () => advanceOperation(attempted, { type: "record_dropped", identity, drop }),
      "operation_transition_invalid",
    );

    const keyedIdentity = { ...identity, nonce: (1n << 64n).toString() };
    const keyed = advanceOperation(createOperation({ identity: keyedIdentity, preparedAt: 10 }), {
      type: "mark_submission_attempted",
      identity: keyedIdentity,
      attemptedAt: 11,
    });
    expectOperationError(
      () =>
        advanceOperation(keyed, {
          type: "record_dropped",
          identity: keyedIdentity,
          drop: { ...drop, observedNonce: (2n << 64n).toString() },
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
    const exhausted = {
      ...createOperation({ identity, preparedAt: 10 }),
      revision: Number.MAX_SAFE_INTEGER,
    };
    expectOperationError(
      () =>
        advanceOperation(exhausted, {
          type: "mark_submission_attempted",
          identity,
          attemptedAt: 11,
        }),
      "operation_revision_exhausted",
    );
  });
});
