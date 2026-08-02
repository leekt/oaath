import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  advanceOperation,
  createOperation,
  OgpOperationError,
  type Operation,
  type OperationIdentity,
  type OperationOutcome,
  operationOccupiesLane,
  parseOperation,
} from "../src/index.js";
import { applyVerifiedOperationObservation } from "../src/operation.js";

const identity: OperationIdentity = {
  kind: "execution",
  grantId: "grant-1",
  chainId: 31_337,
  entryPoint: `0x${"11".repeat(20)}`,
  account: `0x${"22".repeat(20)}`,
  nonce: "7",
  userOperationHash: `0x${"33".repeat(32)}`,
};

const transactionHash = `0x${"44".repeat(32)}` as const;
const inclusionBlockHash = `0x${"55".repeat(32)}` as const;
const finalityBlockHash = `0x${"66".repeat(32)}` as const;
const replacementUserOperationHash = `0x${"77".repeat(32)}` as const;
const replacementBlockHash = `0x${"88".repeat(32)}` as const;
const replacementTransactionHash = `0x${"99".repeat(32)}` as const;
const replacementFinalityBlockHash = `0x${"aa".repeat(32)}` as const;

function prepared(at = 10): Operation {
  return createOperation({ identity, preparedAt: at });
}

function attempted(operation: Operation, at = 11): Operation {
  return advanceOperation(operation, {
    type: "mark_submission_attempted",
    identity,
    attemptedAt: at,
  });
}

function submitted(operation: Operation, at = 12): Operation {
  return advanceOperation(operation, {
    type: "mark_submitted",
    identity,
    returnedUserOperationHash: identity.userOperationHash,
    submittedAt: at,
  });
}

function included(operation: Operation, outcome: OperationOutcome = "success", at = 13): Operation {
  return applyVerifiedOperationObservation(operation, {
    type: "record_included",
    identity,
    inclusion: {
      transactionHash,
      blockNumber: "20",
      blockHash: inclusionBlockHash,
      outcome,
      observedAt: at,
    },
  });
}

function replacementDrop() {
  return {
    kind: "finalized_nonce_replacement" as const,
    replacement: {
      identity: {
        chainId: identity.chainId,
        entryPoint: identity.entryPoint,
        account: identity.account,
        nonce: identity.nonce,
        userOperationHash: replacementUserOperationHash,
      },
      inclusion: {
        transactionHash: replacementTransactionHash,
        blockNumber: "30",
        blockHash: replacementBlockHash,
        outcome: "reverted" as const,
        observedAt: 13,
      },
      finality: {
        blockNumber: "35",
        blockHash: replacementFinalityBlockHash,
        observedAt: 14,
      },
    },
  };
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

describe("Operation aggregate", () => {
  it("advances one exact acknowledged operation through finalized success", () => {
    const created = prepared();
    expect(created).toMatchObject({ state: "prepared", revision: 0, observation: null });
    expect(Object.isFrozen(created)).toBe(true);
    expect(Object.isFrozen(created.identity)).toBe(true);

    const sent = submitted(attempted(created));
    const observed = included(sent, "success");
    const finalized = applyVerifiedOperationObservation(observed, {
      type: "record_finalized",
      identity,
      finality: {
        blockNumber: "25",
        blockHash: finalityBlockHash,
        observedAt: 14,
      },
    });

    expect(finalized).toMatchObject({
      state: "finalized",
      revision: 4,
      submittedAt: 12,
      inclusion: { outcome: "success" },
      finality: { blockNumber: "25" },
    });
    expect(operationOccupiesLane(created)).toBe(true);
    expect(operationOccupiesLane(observed)).toBe(true);
    expect(operationOccupiesLane(finalized)).toBe(false);
    expect(parseOperation(JSON.parse(JSON.stringify(finalized)))).toEqual(finalized);
  });

  it("observes reverted inclusion directly from submission_attempted", () => {
    const observed = included(attempted(prepared()), "reverted", 12);
    expect(observed).toMatchObject({
      state: "included",
      revision: 2,
      submittedAt: null,
      inclusion: { outcome: "reverted" },
    });
  });

  it("retains stronger inclusion through pending and unreadable observations", () => {
    let operation = attempted(prepared());
    operation = applyVerifiedOperationObservation(operation, {
      type: "record_pending",
      identity,
      observedAt: 12,
      reason: "timeout",
    });
    expect(operation).toMatchObject({
      state: "submission_attempted",
      observation: { status: "pending" },
    });

    operation = included(operation, "success", 13);
    operation = applyVerifiedOperationObservation(operation, {
      type: "record_unreadable",
      identity,
      observedAt: 14,
      reason: "provider_unavailable",
    });
    expect(operation).toMatchObject({
      state: "included",
      inclusion: { transactionHash, outcome: "success" },
      observation: { status: "unreadable" },
    });

    operation = applyVerifiedOperationObservation(operation, {
      type: "record_pending",
      identity,
      observedAt: 15,
      reason: "receipt_missing",
    });
    expect(operation).toMatchObject({
      state: "included",
      inclusion: { transactionHash },
      observation: { status: "pending" },
    });
  });

  it("uses positive finalized nonce replacement as the only dropped transition", () => {
    const waiting = applyVerifiedOperationObservation(attempted(prepared()), {
      type: "record_unreadable",
      identity,
      observedAt: 12,
      reason: "canonicality_unproven",
    });
    expect(waiting.state).toBe("submission_attempted");

    const dropped = applyVerifiedOperationObservation(waiting, {
      type: "record_dropped",
      identity,
      drop: replacementDrop(),
    });
    expect(dropped).toMatchObject({
      state: "dropped",
      attemptedAt: 11,
      submittedAt: null,
      priorInclusion: null,
      drop: { kind: "finalized_nonce_replacement" },
    });
    if (dropped.state !== "dropped") throw new Error("Expected dropped operation");
    expect(Object.isFrozen(dropped.drop)).toBe(true);
    expect(Object.isFrozen(dropped.drop.replacement)).toBe(true);
    expect(Object.isFrozen(dropped.drop.replacement.identity)).toBe(true);
    expect(operationOccupiesLane(dropped)).toBe(false);
  });

  it("retains prior inclusion when positive evidence later proves dropped", () => {
    const prior = included(attempted(prepared()), "success", 12);
    const dropped = applyVerifiedOperationObservation(prior, {
      type: "record_dropped",
      identity,
      drop: replacementDrop(),
    });
    expect(dropped).toMatchObject({
      state: "dropped",
      priorInclusion: { transactionHash, outcome: "success" },
    });
  });

  it("rejects forbidden transitions and identity substitution with structured codes", () => {
    expectOperationError(() => submitted(prepared()), "operation_transition_forbidden");

    const waiting = attempted(prepared());
    expectOperationError(() => attempted(waiting), "operation_transition_forbidden");

    expectOperationError(
      () =>
        applyVerifiedOperationObservation(waiting, {
          type: "record_pending",
          identity: { ...identity, chainId: identity.chainId + 1 },
          observedAt: 12,
          reason: "timeout",
        }),
      "operation_identity_mismatch",
    );

    expectOperationError(
      () =>
        advanceOperation(waiting, {
          type: "mark_submitted",
          identity,
          returnedUserOperationHash: `0x${"99".repeat(32)}`,
          submittedAt: 12,
        }),
      "operation_identity_mismatch",
    );

    expectOperationError(
      () =>
        applyVerifiedOperationObservation(prepared(), {
          type: "record_dropped",
          identity,
          drop: replacementDrop(),
        }),
      "operation_transition_forbidden",
    );
  });

  it("does not let public callers fabricate observation transitions", () => {
    const waiting = attempted(prepared());
    expectOperationError(
      () =>
        advanceOperation(waiting, {
          type: "record_included",
          identity,
          inclusion: {
            transactionHash,
            blockNumber: "20",
            blockHash: inclusionBlockHash,
            outcome: "success",
            observedAt: 12,
          },
        }),
      "operation_transition_forbidden",
    );
  });

  it("rejects regressing time and leaves terminal operations immutable", () => {
    const waiting = attempted(prepared(10), 11);
    expectOperationError(
      () =>
        applyVerifiedOperationObservation(waiting, {
          type: "record_pending",
          identity,
          observedAt: 10,
          reason: "timeout",
        }),
      "operation_transition_invalid",
    );

    const final = applyVerifiedOperationObservation(included(waiting, "success", 12), {
      type: "record_finalized",
      identity,
      finality: { blockNumber: "25", blockHash: finalityBlockHash, observedAt: 13 },
    });
    const afterUnreadable = applyVerifiedOperationObservation(final, {
      type: "record_unreadable",
      identity,
      observedAt: 14,
      reason: "provider_unavailable",
    });
    expect(afterUnreadable).toEqual(final);
  });

  it("snapshots caller-owned identity before later mutation", () => {
    const mutable = { ...identity };
    const operation = createOperation({ identity: mutable, preparedAt: 10 });
    mutable.grantId = "changed";
    mutable.chainId += 1;
    mutable.userOperationHash = `0x${"aa".repeat(32)}`;
    expect(operation.identity).toEqual(identity);
  });

  it("property-checks both inclusion outcomes across monotonic timestamps", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 1_000_000 }),
        fc.constantFrom<OperationOutcome>("success", "reverted"),
        (start, outcome) => {
          const observed = included(attempted(prepared(start), start + 1), outcome, start + 2);
          expect(observed).toMatchObject({ state: "included", inclusion: { outcome } });
          expect(observed.identity).toEqual(identity);
        },
      ),
    );
  });

  it("property-checks that an attempted operation never regains submission", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 1_000_000 }), (start) => {
        const waiting = attempted(prepared(start), start + 1);
        expectOperationError(() => attempted(waiting, start + 2), "operation_transition_forbidden");
      }),
    );
  });
});
