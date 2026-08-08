/**
 * Final EIP-5792 status projection from OAAth-owned operation evidence.
 *
 * @author taek <leekt216@gmail.com>
 */
import { advanceOperation, createOperation, type OperationIdentity } from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import {
  type OaathOperationLog,
  type OaathOperationOutcome,
  type OaathOperationReceipt,
  operationOutcome as projectOperationOutcome,
} from "../src/client/operation-handle.js";
import { type Eip5792CallsStatus, projectEip5792Status } from "../src/provider/status.js";

const TRANSACTION_HASH = `0x${"11".repeat(32)}` as `0x${string}`;
const OTHER_TRANSACTION_HASH = `0x${"12".repeat(32)}` as `0x${string}`;
const BLOCK_HASH = `0x${"22".repeat(32)}` as `0x${string}`;
const FIRST_TOPIC = `0x${"33".repeat(32)}` as `0x${string}`;
const SECOND_TOPIC = `0x${"44".repeat(32)}` as `0x${string}`;
const RESULT_CAPABILITIES = Object.freeze({
  paymasterService: Object.freeze({
    sponsor: Object.freeze({
      name: "Example Sponsor",
      icon: "data:image/png;base64,AQ==",
    }),
  }),
});
const ABANDONED_IDENTITY: OperationIdentity = {
  kind: "execution",
  grantId: "abandoned-status",
  chainId: 421_614,
  entryPoint: `0x${"55".repeat(20)}`,
  account: `0x${"66".repeat(20)}`,
  nonce: "7",
  userOperationHash: `0x${"77".repeat(32)}`,
  requestHash: null,
};

function operationOutcome(overrides: Partial<OaathOperationOutcome> = {}): OaathOperationOutcome {
  return {
    status: "pending",
    state: "submitted",
    transactionHash: null,
    blockNumber: null,
    outcome: null,
    reason: null,
    ...overrides,
  };
}

function finalizedOutcome(
  result: "success" | "reverted" = "success",
  overrides: Partial<OaathOperationOutcome> = {},
): OaathOperationOutcome {
  return operationOutcome({
    status: "finalized",
    state: "finalized",
    transactionHash: TRANSACTION_HASH,
    blockNumber: "2748",
    outcome: result,
    ...overrides,
  });
}

function operationReceipt(
  status: "success" | "reverted" = "success",
  overrides: Partial<OaathOperationReceipt> = {},
): OaathOperationReceipt {
  return {
    transactionHash: TRANSACTION_HASH,
    blockHash: BLOCK_HASH,
    blockNumber: "2748",
    gasUsed: "3567",
    transactionStatus: "success",
    status,
    logs: [
      {
        address: `0x${"55".repeat(20)}`,
        topics: [FIRST_TOPIC],
        data: "0x0102",
      },
      {
        address: `0x${"66".repeat(20)}`,
        topics: [SECOND_TOPIC, FIRST_TOPIC],
        data: "0x0304",
      },
    ],
    ...overrides,
  };
}

function project(
  outcome: OaathOperationOutcome,
  receipt?: OaathOperationReceipt | null,
  id = "Application-ID/Keep-Exact",
): Readonly<Eip5792CallsStatus> {
  return receipt === undefined
    ? projectEip5792Status({ id, chainId: 421_614, outcome })
    : projectEip5792Status({ id, chainId: 421_614, outcome, receipt });
}

describe("Final EIP-5792 status projection", () => {
  it("projects the already-captured display capability without changing status meaning", () => {
    const result = projectEip5792Status({
      id: "sponsored",
      chainId: 421_614,
      outcome: operationOutcome(),
      resultCapabilities: RESULT_CAPABILITIES,
    });

    expect(result).toEqual({
      version: "2.0.0",
      id: "sponsored",
      chainId: "0x66eee",
      atomic: true,
      capabilities: RESULT_CAPABILITIES,
      status: 100,
    });
  });

  it("projects the operation handle outcome from exact abandonment evidence", () => {
    const abandoned = advanceOperation(
      createOperation({ identity: ABANDONED_IDENTITY, preparedAt: 10 }),
      {
        type: "mark_abandoned",
        identity: ABANDONED_IDENTITY,
        abandonedAt: 11,
        reason: "submission_not_attempted",
      },
    );
    if (abandoned.state !== "abandoned") throw new Error("expected abandoned operation");

    const outcome = projectOperationOutcome({
      status: "observed",
      observation: { status: "abandoned", operation: abandoned },
      record: {
        version: "oaath.operation-store-record/v2",
        storeRevision: 1,
        updatedAt: abandoned.updatedAt,
        value: abandoned,
      },
    });

    expect(outcome).toEqual({
      status: "abandoned",
      state: "abandoned",
      transactionHash: null,
      blockNumber: null,
      outcome: null,
      reason: "submission_not_attempted",
    });
  });

  it.each(["prepared", "submission_attempted", "submitted", "included"] as const)(
    "maps nonterminal operation state %s to pending",
    (state) => {
      const included = state === "included";
      const result = project(
        operationOutcome({
          state,
          transactionHash: included ? TRANSACTION_HASH : null,
          blockNumber: included ? "2748" : null,
          outcome: included ? "success" : null,
        }),
      );

      expect(result).toEqual({
        version: "2.0.0",
        id: "Application-ID/Keep-Exact",
        chainId: "0x66eee",
        atomic: true,
        status: 100,
      });
    },
  );

  it.each(["pending", "unreadable"] as const)("maps %s observations to 100", (status) => {
    const result = project(
      operationOutcome({
        status,
        state: "included",
        transactionHash: TRANSACTION_HASH,
        blockNumber: "2748",
        outcome: "success",
      }),
      operationReceipt(),
    );

    expect(result.status).toBe(100);
    expect("receipts" in result).toBe(false);
  });

  it("projects finalized success with exact base fields and one canonical receipt", () => {
    const result = project(finalizedOutcome(), operationReceipt());

    expect(result).toEqual({
      version: "2.0.0",
      id: "Application-ID/Keep-Exact",
      chainId: "0x66eee",
      atomic: true,
      status: 200,
      receipts: [
        {
          logs: [
            {
              address: `0x${"55".repeat(20)}`,
              topics: [FIRST_TOPIC],
              data: "0x0102",
            },
            {
              address: `0x${"66".repeat(20)}`,
              topics: [SECOND_TOPIC, FIRST_TOPIC],
              data: "0x0304",
            },
          ],
          status: "0x1",
          blockHash: BLOCK_HASH,
          blockNumber: "0xabc",
          gasUsed: "0xdef",
          transactionHash: TRANSACTION_HASH,
        },
      ],
    });
  });

  it("projects finalized full UserOperation revert as 500 with containing receipt status 0x1", () => {
    const result = project(finalizedOutcome("reverted"), operationReceipt("reverted"));

    expect(result.status).toBe(500);
    expect("receipts" in result && result.receipts[0].status).toBe("0x1");
  });

  it.each([
    operationOutcome({
      status: "dropped",
      state: "dropped",
      transactionHash: TRANSACTION_HASH,
      blockNumber: "2748",
      outcome: "success",
    }),
    operationOutcome({
      status: "abandoned",
      state: "abandoned",
      reason: "submission_not_attempted",
    }),
  ])("maps terminal non-inclusion to 400 without receipts", (outcome) => {
    const result = project(outcome, operationReceipt());

    expect(result.status).toBe(400);
    expect("receipts" in result).toBe(false);
  });

  it("keeps nonce-superseded execution ambiguous without a receipt", () => {
    const result = project(operationOutcome({ status: "superseded", state: "superseded" }));

    expect(result).toMatchObject({ status: 100 });
    expect("receipts" in result).toBe(false);
  });

  it.each([
    [
      "missing transaction",
      finalizedOutcome("success", { transactionHash: null }),
      operationReceipt(),
    ],
    ["missing block", finalizedOutcome("success", { blockNumber: null }), operationReceipt()],
    ["missing outcome", finalizedOutcome("success", { outcome: null }), operationReceipt()],
    ["missing receipt", finalizedOutcome(), null],
    ["non-finalized state", finalizedOutcome("success", { state: "included" }), operationReceipt()],
    [
      "transaction disagreement",
      finalizedOutcome(),
      operationReceipt("success", { transactionHash: OTHER_TRANSACTION_HASH }),
    ],
    [
      "block disagreement",
      finalizedOutcome(),
      operationReceipt("success", { blockNumber: "2749" }),
    ],
    ["status disagreement", finalizedOutcome(), operationReceipt("reverted")],
    [
      "noncanonical block",
      finalizedOutcome(),
      operationReceipt("success", { blockNumber: "02748" }),
    ],
    ["noncanonical gas", finalizedOutcome(), operationReceipt("success", { gasUsed: "03567" })],
  ] as const)("fails closed on %s", (_label, outcome, receipt) => {
    expect(() => project(outcome, receipt)).toThrowError(
      expect.objectContaining({ name: "OaathProviderRpcError" }),
    );
  });

  it("returns a deeply immutable copy while preserving every supplied log in order", () => {
    const topics = [FIRST_TOPIC];
    const logs: OaathOperationLog[] = [
      {
        address: `0x${"55".repeat(20)}`,
        topics,
        data: "0x0102",
      },
      {
        address: `0x${"66".repeat(20)}`,
        topics: [SECOND_TOPIC],
        data: "0x0304",
      },
    ];
    const result = project(finalizedOutcome(), operationReceipt("success", { logs }));
    if (!("receipts" in result)) throw new Error("expected terminal receipt projection");
    const projectedLogs = result.receipts[0].logs;

    expect(projectedLogs).toEqual(logs);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.receipts)).toBe(true);
    expect(Object.isFrozen(result.receipts[0])).toBe(true);
    expect(Object.isFrozen(projectedLogs)).toBe(true);
    expect(projectedLogs.every(Object.isFrozen)).toBe(true);
    expect(projectedLogs.every((log) => Object.isFrozen(log.topics))).toBe(true);
    expect(Reflect.set(result, "status", 600)).toBe(false);

    topics.push(SECOND_TOPIC);
    logs.reverse();
    expect(projectedLogs).toEqual([
      { address: `0x${"55".repeat(20)}`, topics: [FIRST_TOPIC], data: "0x0102" },
      { address: `0x${"66".repeat(20)}`, topics: [SECOND_TOPIC], data: "0x0304" },
    ]);
  });

  it("has no partial-revert 600 projection", () => {
    const statuses = [
      project(operationOutcome({ state: "prepared" })).status,
      project(finalizedOutcome(), operationReceipt()).status,
      project(finalizedOutcome("reverted"), operationReceipt("reverted")).status,
      project(operationOutcome({ status: "dropped", state: "dropped" })).status,
      project(operationOutcome({ status: "superseded", state: "superseded" })).status,
      project(
        operationOutcome({
          status: "abandoned",
          state: "abandoned",
          reason: "submission_not_attempted",
        }),
      ).status,
    ];

    expect(statuses).toEqual([100, 200, 500, 400, 100, 400]);
    expect(statuses).not.toContain(600);
  });
});
