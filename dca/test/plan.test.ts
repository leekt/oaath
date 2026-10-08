import {
  type AutomationDefinition,
  createPlanTerms,
  derivePlanPolicy,
  functionSelector,
  parseAutomation,
  type Run,
  resolveCalls,
} from "@oaath/automation";
import { decodeFunctionData, getAddress } from "viem";
import { describe, expect, it } from "vitest";
import executor from "../../examples/dca/contracts/artifacts/DcaExecutor.json" with {
  type: "json",
};
import template from "../../examples/dca/dca-arbsep.automation.json" with { type: "json" };
import {
  BUY_TOKEN_DATA,
  balanceOfData,
  dcaOptions,
  decodeAddress,
  decodeUint,
  formatUnits,
  intervalLabel,
  type PlanInputError,
  parseAmount,
  planRequest,
  runRows,
  START_DELAY_SECONDS,
} from "../src/plan.js";
import { DCA_AUTOMATION_PREFIX } from "../worker/index.js";

const SELL = "0x1111111111111111111111111111111111111111";
const DCA = "0x2222222222222222222222222222222222222222";
const ACCOUNT = `0x${"ab".repeat(20)}` as const;
const NOW = 1_800_000_000;

/** The service definitions as deployed: placeholders filled the way deploy-arbsep.sh does. */
function deployed(): AutomationDefinition[] {
  const filled = JSON.stringify(template)
    .replaceAll("REPLACE_SELL_TOKEN", SELL)
    .replaceAll("REPLACE_DCA_EXECUTOR", DCA);
  return (JSON.parse(filled) as unknown[]).map(parseAutomation);
}

describe("Arbitrum Sepolia DCA definitions", () => {
  it("refuses to load until the deployed addresses are filled in", () => {
    for (const entry of template) expect(() => parseAutomation(entry)).toThrow();
  });

  it("offers one definition per interval, each within the executor's plan rules", () => {
    const options = dcaOptions(deployed(), DCA_AUTOMATION_PREFIX, 421_614);
    expect(options.map((option) => [option.id, option.every])).toEqual([
      ["dca.arbsep.1m.v1", 60],
      ["dca.arbsep.5m.v1", 300],
      ["dca.arbsep.1h.v1", 3600],
    ]);
    for (const option of options) {
      // DcaExecutor.open: interval >= 60, 0 < grace <= interval, runs <= 1000.
      expect(option.every).toBeGreaterThanOrEqual(60);
      expect(option.grace).toBeGreaterThan(0);
      expect(option.grace).toBeLessThanOrEqual(option.every);
      expect(option.maxBuys).toBeLessThanOrEqual(1000);
      expect(option).toMatchObject({ sellToken: SELL, executor: DCA, maxBudget: 1_000_000_000n });
    }
    expect(dcaOptions(deployed(), DCA_AUTOMATION_PREFIX, 1)).toEqual([]);
  });

  it("declares the executor functions exactly as the DcaExecutor artifact does", () => {
    const abi = executor.abi as { type: string; name?: string; inputs?: { type: string }[] }[];
    for (const definition of deployed()) {
      for (const item of definition.contracts.dca?.abi ?? []) {
        const built = abi.find((entry) => entry.type === "function" && entry.name === item.name);
        expect(item.inputs?.map((input) => input.type)).toEqual(
          built?.inputs?.map((input) => input.type),
        );
      }
    }
  });

  it("mints the budget to the plan's account, approves it, opens the plan, then buys per slot", () => {
    const definition = deployed()[0] as AutomationDefinition;
    const option = dcaOptions([definition], DCA_AUTOMATION_PREFIX, 421_614)[0]!;
    const request = planRequest(option, "2.5", 4, NOW, "key");
    const { automation: _, idempotencyKey: __, ...input } = request;
    const terms = createPlanTerms(definition, {
      planId: `0x${"cd".repeat(32)}`,
      account: ACCOUNT,
      now: NOW,
      ...input,
    });
    const abi = [
      ...(definition.contracts.token?.abi ?? []),
      ...(definition.contracts.dca?.abi ?? []),
    ];
    const decode = (data: `0x${string}`) => decodeFunctionData({ abi: abi as never, data });
    const setup = resolveCalls(definition, terms, "setup");
    expect(setup.map((call) => call.target)).toEqual([SELL, SELL, DCA]);
    expect(setup.map((call) => decode(call.data))).toEqual([
      { functionName: "mint", args: [getAddress(ACCOUNT), 10_000_000n] },
      { functionName: "approve", args: [getAddress(DCA), 10_000_000n] },
      {
        functionName: "open",
        args: [
          `0x${"cd".repeat(32)}`,
          10_000_000n,
          4,
          BigInt(NOW + START_DELAY_SECONDS),
          60,
          50,
          300,
        ],
      },
    ]);
    expect(decode(resolveCalls(definition, terms, { slot: 3 })[0]!.data)).toEqual({
      functionName: "execute",
      args: [`0x${"cd".repeat(32)}`, 3],
    });
    const policy = derivePlanPolicy(definition, terms, NOW);
    expect(policy.calls.map((call) => [call.target, call.selector, call.valueLimit])).toEqual(
      [
        [SELL, functionSelector("approve", ["address", "uint256"]), "0"],
        [SELL, functionSelector("mint", ["address", "uint256"]), "0"],
        [DCA, functionSelector("cancel", ["bytes32"]), "0"],
        [DCA, functionSelector("execute", ["bytes32", "uint32"]), "0"],
        [
          DCA,
          functionSelector("open", [
            "bytes32",
            "uint256",
            "uint32",
            "uint64",
            "uint32",
            "uint32",
            "uint16",
          ]),
          "0",
        ],
      ].sort(([a, b], [c, d]) => (`${a}:${b}` < `${c}:${d}` ? -1 : 1)),
    );
    // Four buys, the setup and the cancellation.
    expect(policy.perChainOperationLimit.count).toBe(6);
  });
});

describe("plan form", () => {
  const option = dcaOptions(deployed(), DCA_AUTOMATION_PREFIX, 421_614)[1]!;

  it("parses tUSD amounts in base units and refuses anything else", () => {
    expect(parseAmount("1", 6)).toBe(1_000_000n);
    expect(parseAmount(" 0.25 ", 6)).toBe(250_000n);
    expect(parseAmount("1.000001", 6)).toBe(1_000_001n);
    for (const bad of ["0", "0.0", "1.0000001", "-1", "1e3", "", "abc", ".5"])
      expect(parseAmount(bad, 6)).toBeNull();
  });

  it("asks for amount × buys as the budget, starting after the approval delay", () => {
    expect(planRequest(option, "1.5", 3, NOW, "key")).toEqual({
      automation: "dca.arbsep.5m.v1",
      params: { budget: "4500000", maxSlippageBps: "300" },
      occurrences: 3,
      startAt: NOW + START_DELAY_SECONDS,
      idempotencyKey: "key",
    });
  });

  it("refuses a bad amount, a buy count outside the definition, and an over-cap budget", () => {
    const code = (run: () => unknown) => {
      try {
        run();
      } catch (error) {
        return (error as PlanInputError).code;
      }
      return null;
    };
    expect(code(() => planRequest(option, "0", 3, NOW, "k"))).toBe("amount_invalid");
    expect(code(() => planRequest(option, "1", 0, NOW, "k"))).toBe("buys_invalid");
    expect(code(() => planRequest(option, "1", 21, NOW, "k"))).toBe("buys_invalid");
    expect(code(() => planRequest(option, "1", 2.5, NOW, "k"))).toBe("buys_invalid");
    expect(code(() => planRequest(option, "100", 11, NOW, "k"))).toBe("budget_too_large");
    expect(code(() => planRequest(option, "100", 10, NOW, "k"))).toBeNull();
  });

  it("formats units and intervals", () => {
    expect(formatUnits(4_500_000n, 6)).toBe("4.5");
    expect(formatUnits(1_234_567_890_123_456_789n, 18, 6)).toBe("1.234567");
    expect(formatUnits(0n, 18)).toBe("0");
    expect([60, 300, 3600, 86_400, 90].map(intervalLabel)).toEqual([
      "1 minute",
      "5 minutes",
      "1 hour",
      "1 day",
      "90 seconds",
    ]);
  });
});

describe("watching a plan", () => {
  const run = (overrides: Partial<Run>): Run => ({
    kind: "occurrence",
    slot: 0,
    status: "due",
    scheduledAt: NOW,
    closesAt: NOW + 50,
    operation: null,
    transactionHash: null,
    reason: null,
    ...overrides,
  });
  const schedule = { startAt: NOW, every: 60, occurrences: 3 };
  const TX = `0x${"ee".repeat(32)}` as const;

  it("shows the setup and every buy in order, upcoming until the service schedules it", () => {
    const rows = runRows(
      [
        run({ slot: 0, status: "finalized", transactionHash: TX }),
        run({ kind: "setup", slot: null, status: "observed", transactionHash: TX }),
      ],
      schedule,
      "https://sepolia.arbiscan.io/tx/",
    );
    expect(rows.map((row) => [row.label, row.status, row.tone, row.transactionUrl])).toEqual([
      [
        "Setup: mint test tUSD, approve, open plan",
        "Included",
        "done",
        `https://sepolia.arbiscan.io/tx/${TX}`,
      ],
      ["Buy 1 of 3", "Finalized", "done", `https://sepolia.arbiscan.io/tx/${TX}`],
      ["Buy 2 of 3", "Upcoming", "pending", null],
      ["Buy 3 of 3", "Upcoming", "pending", null],
    ]);
    expect(rows.map((row) => row.at)).toEqual([NOW, NOW, NOW + 60, NOW + 120]);
  });

  it("marks submitted, missed and failed buys, and links only a known transaction", () => {
    const rows = runRows(
      [
        run({ slot: 0, status: "submitted", operation: TX }),
        run({ slot: 1, status: "skipped" }),
        run({ slot: 2, status: "failed" }),
        run({ kind: "cancel", slot: null, status: "due" }),
      ],
      schedule,
      null,
    );
    expect(rows.slice(1).map((row) => [row.status, row.tone, row.transactionUrl])).toEqual([
      ["Submitted", "active", null],
      ["Missed its window", "failed", null],
      ["Failed", "failed", null],
      ["Due", "active", null],
    ]);
  });

  it("encodes balance reads and decodes only well-formed answers", () => {
    expect(balanceOfData(ACCOUNT)).toBe(`0x70a08231${"0".repeat(24)}${"ab".repeat(20)}`);
    expect(BUY_TOKEN_DATA).toBe(functionSelector("buyToken", []));
    expect(decodeAddress(`0x${"0".repeat(24)}${"AB".repeat(20)}`)).toBe(ACCOUNT);
    expect(decodeAddress(`0x${"1".repeat(64)}`)).toBeNull();
    expect(decodeUint(`0x${"0".repeat(63)}a`)).toBe(10n);
    expect(decodeUint("0x")).toBeNull();
    expect(decodeUint(null)).toBeNull();
  });
});
