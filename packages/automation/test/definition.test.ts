import { OAATH_GRANT_POLICY_VERSION } from "@oaath/protocol";
import { decodeFunctionData } from "cetane/utils";
import { describe, expect, it } from "vitest";
import {
  createPlanTerms,
  defineAutomation,
  derivePlanPolicy,
  functionSelector,
  hashAutomation,
  hashPlanTerms,
  type OnDemandAutomationDefinitionInput,
  parseAutomation,
  planEnd,
  resolveCalls,
  type ScheduledAutomationDefinitionInput,
  slotTime,
} from "../src/index.js";

const token = "0x1111111111111111111111111111111111111111";
const vault = "0x2222222222222222222222222222222222222222";
const fn = (name: string, inputs: string[]) => ({
  type: "function",
  name,
  stateMutability: "nonpayable",
  inputs: inputs.map((type, index) => ({ name: `a${index}`, type })),
  outputs: [],
});

/** A DCA-shaped definition: setup, a recurring call and a cancellation. */
const input = (): ScheduledAutomationDefinitionInput => ({
  id: "recurring.v1",
  name: "Recurring purchase",
  chainId: 31337,
  contracts: {
    token: { address: token, abi: [fn("approve", ["address", "uint256"])] },
    vault: {
      address: vault,
      abi: [
        fn("open", ["bytes32", "uint256", "uint32", "uint64", "uint32", "uint32", "uint16"]),
        fn("execute", ["bytes32", "uint32"]),
        fn("cancel", ["bytes32"]),
        { type: "event", name: "Purchased", inputs: [] },
      ],
    },
  },
  params: {
    budget: { type: "uint256", decimals: 6, min: "1" },
    maxSlippageBps: { type: "uint16", max: "1000" },
  },
  schedule: { every: "1d", count: { max: 30 }, grace: "15m" },
  setup: [
    { contract: "token", function: "approve", args: ["$contract.vault", "$param.budget"] },
    {
      contract: "vault",
      function: "open",
      args: [
        "$plan.id",
        "$param.budget",
        "$plan.occurrences",
        "$plan.startAt",
        "$plan.every",
        "$plan.grace",
        "$param.maxSlippageBps",
      ],
    },
  ],
  call: { contract: "vault", function: "execute", args: ["$plan.id", "$slot.index"] },
  cancel: [
    { contract: "vault", function: "cancel", args: ["$plan.id"] },
    { contract: "token", function: "approve", args: ["$contract.vault", "0"] },
  ],
});

const planId = `0x${"ab".repeat(32)}` as const;
const account = "0x3333333333333333333333333333333333333333" as const;
const now = 1_800_000_000;
const terms = () =>
  createPlanTerms(defineAutomation(input()), {
    planId,
    account,
    now,
    params: { budget: "30000000", maxSlippageBps: "50" },
    occurrences: 30,
    startAt: now + 600,
  });

describe("defineAutomation", () => {
  it("normalizes durations and freezes the definition", () => {
    const definition = defineAutomation(input());
    expect(definition.schedule).toEqual({ every: 86400, count: { min: 1, max: 30 }, grace: 900 });
    expect(Object.isFrozen(definition)).toBe(true);
    expect(parseAutomation(JSON.parse(JSON.stringify(definition)))).toEqual(definition);
    expect(hashAutomation(parseAutomation(JSON.parse(JSON.stringify(definition))))).toBe(
      hashAutomation(definition),
    );
  });

  it.each([
    ["an undeclared function", (d: any) => (d.call.function = "sweep")],
    ["an undeclared contract", (d: any) => (d.call.contract = "router")],
    ["a wrong argument count", (d: any) => d.call.args.pop()],
    ["an unknown reference", (d: any) => (d.call.args[1] = "$slot.when")],
    ["an undeclared parameter", (d: any) => (d.setup[0].args[1] = "$param.amount")],
    ["a slot reference outside the occurrence", (d: any) => (d.setup[0].args[1] = "$slot.index")],
    ["an address into a uint", (d: any) => (d.setup[0].args[1] = "$contract.vault")],
    ["a value above the limit", (d: any) => (d.call.value = "1")],
    ["grace longer than the interval", (d: any) => (d.schedule.grace = "2d")],
    ["a sub-minute interval", (d: any) => (d.schedule.every = 30)],
    ["an unknown field", (d: any) => (d.script = "x")],
    [
      "an overloaded function",
      (d: any) => d.contracts.vault.abi.push(fn("execute", ["bytes32", "uint32", "uint256"])),
    ],
    [
      "a dynamic ABI type",
      (d: any) => {
        d.contracts.vault.abi[1] = fn("execute", ["bytes", "uint32"]);
      },
    ],
  ])("rejects %s", (_, change) => {
    const definition = structuredClone(input()) as any;
    change(definition);
    expect(() => defineAutomation(definition)).toThrow(
      expect.objectContaining({ code: "automation_definition_invalid" }),
    );
  });
});

describe("plans", () => {
  it("freezes parameters and the schedule and resolves exact calls", () => {
    const definition = defineAutomation(input());
    const plan = terms();
    expect(plan.schedule).toEqual({
      startAt: now + 600,
      every: 86400,
      grace: 900,
      occurrences: 30,
      endAt: now + 600 + 29 * 86400 + 900,
    });
    expect(slotTime(plan, 2)).toBe(now + 600 + 2 * 86400);
    const [call] = resolveCalls(definition, plan, { slot: 7 });
    expect(call?.target).toBe(vault);
    const abi = definition.contracts.vault?.abi as never;
    expect(decodeFunctionData({ abi, data: call?.data as `0x${string}` } as never)).toMatchObject({
      functionName: "execute",
      args: [planId, 7],
    });
    const setup = resolveCalls(definition, plan, "setup");
    expect(setup.map((entry) => entry.target)).toEqual([token, vault]);
    expect(() => resolveCalls(definition, plan, { slot: 30 })).toThrow();
    expect(hashPlanTerms(plan)).toBe(hashPlanTerms(terms()));
  });

  it.each([
    [{ params: { budget: "0", maxSlippageBps: "50" } }, "plan_param_out_of_bounds"],
    [{ params: { budget: "1", maxSlippageBps: "1001" } }, "plan_param_out_of_bounds"],
    [{ params: { budget: "1" } }, "plan_param_missing"],
    [{ params: { budget: "1", maxSlippageBps: "1", extra: "1" } }, "plan_param_invalid"],
    [{ params: { budget: "01", maxSlippageBps: "1" } }, "plan_param_invalid"],
    [{ occurrences: 31 }, "plan_occurrences_invalid"],
    [{ startAt: now - 1 }, "plan_start_invalid"],
  ])("rejects plan input %j", (change, code) => {
    expect(() =>
      createPlanTerms(defineAutomation(input()), {
        planId,
        account,
        now,
        params: { budget: "30", maxSlippageBps: "50" },
        occurrences: 30,
        ...change,
      }),
    ).toThrow(expect.objectContaining({ code }));
  });

  it("refuses a parameter that cannot be encoded into its call", () => {
    const definition = structuredClone(input()) as any;
    definition.params.budget = { type: "uint256" };
    definition.setup[1].args[2] = "$param.budget";
    expect(() =>
      createPlanTerms(defineAutomation(definition), {
        planId,
        account,
        now,
        params: { budget: String(2n ** 40n), maxSlippageBps: "1" },
        occurrences: 3,
      }),
    ).toThrow(expect.objectContaining({ code: "plan_call_unencodable" }));
  });
});

describe("derivePlanPolicy", () => {
  it("allow-lists exactly the declared functions for the schedule window", () => {
    const definition = defineAutomation(input());
    const policy = derivePlanPolicy(definition, terms(), now);
    expect(policy.version).toBe(OAATH_GRANT_POLICY_VERSION);
    expect(policy.calls.map((call) => [call.target, call.selector])).toEqual(
      [
        [token, functionSelector("approve", ["address", "uint256"])],
        [vault, functionSelector("cancel", ["bytes32"])],
        [vault, functionSelector("execute", ["bytes32", "uint32"])],
        [
          vault,
          functionSelector("open", [
            "bytes32",
            "uint256",
            "uint32",
            "uint64",
            "uint32",
            "uint32",
            "uint16",
          ]),
        ],
      ].sort((a, b) => (`${a[0]}:${a[1]}` < `${b[0]}:${b[1]}` ? -1 : 1)),
    );
    expect(policy.calls.every((call) => call.valueLimit === "0")).toBe(true);
    expect(policy.validAfter).toBe(now);
    expect(policy.validUntil).toBe(terms().schedule.endAt - 1);
    // 30 occurrences, one setup operation and one cancel operation.
    expect(policy.perChainOperationLimit).toEqual({ count: 32, intervalSeconds: null });
  });

  it("counts only the operations a definition declares", () => {
    const bare = structuredClone(input()) as any;
    delete bare.setup;
    delete bare.cancel;
    bare.params = {};
    bare.schedule.count = 5;
    const definition = defineAutomation(bare);
    const plan = createPlanTerms(definition, { planId, account, now });
    expect(derivePlanPolicy(definition, plan, now).perChainOperationLimit?.count).toBe(5);
    expect(derivePlanPolicy(definition, plan, now).calls).toHaveLength(1);
  });
});

describe("on-demand automations", () => {
  const deployer = "0x4444444444444444444444444444444444444444";
  const deploy = "0x9c4ae2d0";
  const onDemand = (): OnDemandAutomationDefinitionInput => ({
    id: "deploy.v1",
    name: "Deploy contracts",
    kind: "on-demand",
    chains: [8453, 1],
    calls: [
      { target: deployer, selector: deploy },
      { target: vault, selector: "0x00000000", valueLimit: "5" },
    ],
    limits: { operationsPerChain: { count: 20, intervalSeconds: 86400 }, maxValidFor: "30d" },
  });

  it("normalizes chains and calls, and round-trips through parseAutomation", () => {
    const definition = defineAutomation(onDemand());
    expect(definition).toMatchObject({
      kind: "on-demand",
      chains: [1, 8453],
      calls: [
        { target: vault, selector: "0x00000000", valueLimit: "5" },
        { target: deployer, selector: deploy, valueLimit: "0" },
      ],
      limits: { operationsPerChain: { count: 20, intervalSeconds: 86400 }, maxValidFor: 2592000 },
    });
    expect(parseAutomation(JSON.parse(JSON.stringify(definition)))).toEqual(definition);
  });

  it.each([
    ["no chains", (d: any) => (d.chains = [])],
    ["a duplicate chain", (d: any) => (d.chains = [1, 1])],
    ["a zero chain", (d: any) => (d.chains = [0])],
    ["no calls", (d: any) => (d.calls = [])],
    ["a duplicate call", (d: any) => d.calls.push({ ...d.calls[0], valueLimit: "9" })],
    ["a short selector", (d: any) => (d.calls[0].selector = "0x1234")],
    ["an invalid target", (d: any) => (d.calls[0].target = "0x1234")],
    ["a non-canonical value limit", (d: any) => (d.calls[0].valueLimit = "05")],
    ["a missing interval", (d: any) => delete d.limits.operationsPerChain.intervalSeconds],
    ["a zero count", (d: any) => (d.limits.operationsPerChain.count = 0)],
    ["a too long validity", (d: any) => (d.limits.maxValidFor = "4000d")],
    ["a schedule", (d: any) => (d.schedule = { every: "1d", count: 1 })],
    ["an unknown kind", (d: any) => (d.kind = "later")],
  ])("rejects %s", (_, change) => {
    const definition = structuredClone(onDemand()) as any;
    change(definition);
    expect(() => defineAutomation(definition)).toThrow(
      expect.objectContaining({ code: "automation_definition_invalid" }),
    );
  });

  it("derives exactly the declared calls, the per-chain limit and validFor", () => {
    const definition = defineAutomation(onDemand());
    const plan = createPlanTerms(definition, { planId, account, now, validFor: 7 * 86400 });
    expect(plan).toMatchObject({
      kind: "on-demand",
      chains: [1, 8453],
      startAt: now,
      endAt: now + 7 * 86400,
    });
    expect(planEnd(plan)).toBe(now + 7 * 86400);
    const policy = derivePlanPolicy(definition, plan, now + 10);
    expect(policy).toEqual({
      version: OAATH_GRANT_POLICY_VERSION,
      calls: definition.calls.map((call) => ({ ...call, argumentEquals: [] })),
      validAfter: now + 10,
      validUntil: now + 7 * 86400 - 1,
      perChainOperationLimit: { count: 20, intervalSeconds: 86400 },
    });
    // Terms of the other kind never derive a policy.
    expect(() => derivePlanPolicy(definition, terms(), now)).toThrow(
      expect.objectContaining({ code: "plan_invalid" }),
    );
  });

  it.each([
    [{}, "plan_valid_for_invalid"],
    [{ validFor: 0 }, "plan_valid_for_invalid"],
    [{ validFor: 30 * 86400 + 1 }, "plan_valid_for_invalid"],
    [{ validFor: 60, occurrences: 1 }, "plan_invalid"],
    [{ validFor: 60, params: {} }, "plan_invalid"],
  ])("rejects on-demand plan input %j", (change, code) => {
    expect(() =>
      createPlanTerms(defineAutomation(onDemand()), { planId, account, now, ...change }),
    ).toThrow(expect.objectContaining({ code }));
  });

  it("refuses validFor on a scheduled plan", () => {
    expect(() =>
      createPlanTerms(defineAutomation(input()), {
        planId,
        account,
        now,
        params: { budget: "30", maxSlippageBps: "50" },
        occurrences: 30,
        validFor: 60,
      }),
    ).toThrow(expect.objectContaining({ code: "plan_invalid" }));
  });
});
