/**
 * Plans: one definition frozen with its parameters and schedule, the calls
 * they resolve to, and the Grant policy derived from them.
 *
 * The policy allow-lists exactly the declared contract functions (Kernel
 * CallPolicy by target and selector), bounds validity to the schedule window,
 * and caps the operation count at the occurrences plus the setup and cancel
 * operations. Argument constraints are not expressible as Kernel policies in
 * OAAth 0.3.x, so the plan's frozen arguments are enforced by the service and
 * the called contracts, not by the account.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type GrantPolicy, OAATH_GRANT_POLICY_VERSION, parseGrantPolicy } from "@oaath/protocol";
import { keccak256, stringToHex } from "cetane/utils";
import {
  type Address,
  type AutomationArgument,
  type AutomationDefinition,
  type AutomationValueType,
  canonicalJson,
  contractFunction,
  encodeCall,
  type Hex,
  hashAutomation,
  type NormalizedAutomationCall,
  uintBits,
} from "./definition.js";
import { AutomationError } from "./error.js";

export const AUTOMATION_PLAN_VERSION = "oaath.automation-plan/v1" as const;

/** Furthest a plan may start in the future. */
const MAX_START_DELAY_SECONDS = 365 * 86400;
const DEFAULT_START_DELAY_SECONDS = 300;

export type AutomationParamValue = string | boolean;

/** What a plan creator chooses; the service supplies identity, account and time. */
export interface AutomationPlanInput {
  readonly params?: Readonly<Record<string, AutomationParamValue>>;
  /** Required when the definition lets the plan choose; must equal a fixed count. */
  readonly occurrences?: number;
  /** Unix seconds of the first occurrence; defaults to five minutes from now. */
  readonly startAt?: number;
}

export interface AutomationPlanSchedule {
  readonly startAt: number;
  readonly every: number;
  readonly grace: number;
  readonly occurrences: number;
  /** Exclusive: the last occurrence's window closes here. */
  readonly endAt: number;
}

/** The frozen, hashed terms a plan executes and its owner approves. */
export interface AutomationPlanTerms {
  readonly version: typeof AUTOMATION_PLAN_VERSION;
  readonly planId: Hex;
  readonly account: Address;
  readonly chainId: number;
  readonly automation: Readonly<{ id: string; hash: Hex }>;
  readonly params: Readonly<Record<string, AutomationParamValue>>;
  readonly schedule: Readonly<AutomationPlanSchedule>;
}

export interface ResolvedCall {
  readonly target: Address;
  readonly value: string;
  readonly data: Hex;
}

function invalid(code: string, message: string): never {
  throw new AutomationError(code, 0, message);
}

function paramValue(
  name: string,
  type: AutomationValueType,
  bounds: Readonly<{ min?: string; max?: string }>,
  value: unknown,
): AutomationParamValue {
  const bits = uintBits(type);
  if (bits !== null) {
    if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,77})$/u.test(value))
      return invalid("plan_param_invalid", `${name} must be a canonical decimal`);
    const amount = BigInt(value);
    if (
      amount >= 1n << BigInt(bits) ||
      (bounds.min !== undefined && amount < BigInt(bounds.min)) ||
      (bounds.max !== undefined && amount > BigInt(bounds.max))
    )
      return invalid("plan_param_out_of_bounds", `${name} is outside its bounds`);
    return value;
  }
  if (type === "bool") {
    if (typeof value !== "boolean") return invalid("plan_param_invalid", `${name} must be bool`);
    return value;
  }
  const pattern = type === "address" ? /^0x[0-9a-fA-F]{40}$/u : /^0x[0-9a-fA-F]{64}$/u;
  if (typeof value !== "string" || !pattern.test(value))
    return invalid("plan_param_invalid", `${name} must be ${type}`);
  return value.toLowerCase();
}

/**
 * Freezes one plan: validated parameters, the concrete schedule, and the
 * definition hash. Every declared call is resolved once here, so a value that
 * cannot be encoded fails at creation rather than at execution.
 */
export function createPlanTerms(
  definition: AutomationDefinition,
  input: Readonly<{ planId: Hex; account: Address; now: number }> & AutomationPlanInput,
): AutomationPlanTerms {
  if (!/^0x[0-9a-f]{64}$/u.test(input.planId) || /^0x0+$/u.test(input.planId))
    invalid("plan_invalid", "planId must be a nonzero lowercase bytes32");
  if (!/^0x[0-9a-f]{40}$/u.test(input.account))
    invalid("plan_invalid", "account must be a lowercase address");
  const supplied = input.params ?? {};
  for (const name of Object.keys(supplied)) {
    if (!Object.hasOwn(definition.params, name))
      invalid("plan_param_invalid", `${name} is not a declared parameter`);
  }
  const params: Record<string, AutomationParamValue> = {};
  for (const [name, param] of Object.entries(definition.params)) {
    if (!Object.hasOwn(supplied, name)) invalid("plan_param_missing", `${name} is required`);
    params[name] = paramValue(name, param.type, param, supplied[name]);
  }
  const { count, every, grace } = definition.schedule;
  const occurrences = input.occurrences ?? (count.min === count.max ? count.min : undefined);
  if (
    occurrences === undefined ||
    !Number.isSafeInteger(occurrences) ||
    occurrences < count.min ||
    occurrences > count.max
  )
    invalid("plan_occurrences_invalid", `occurrences must be ${count.min} to ${count.max}`);
  const startAt = input.startAt ?? input.now + DEFAULT_START_DELAY_SECONDS;
  if (
    !Number.isSafeInteger(startAt) ||
    startAt < input.now ||
    startAt > input.now + MAX_START_DELAY_SECONDS
  )
    invalid("plan_start_invalid", "startAt must be within the next year");
  const terms: AutomationPlanTerms = Object.freeze({
    version: AUTOMATION_PLAN_VERSION,
    planId: input.planId,
    account: input.account,
    chainId: definition.chainId,
    automation: Object.freeze({ id: definition.id, hash: hashAutomation(definition) }),
    params: Object.freeze(params),
    schedule: Object.freeze({
      startAt,
      every,
      grace,
      occurrences: occurrences as number,
      endAt: startAt + ((occurrences as number) - 1) * every + grace,
    }),
  });
  resolveCalls(definition, terms, "setup");
  resolveCalls(definition, terms, "cancel");
  resolveCalls(definition, terms, { slot: 0 });
  resolveCalls(definition, terms, { slot: terms.schedule.occurrences - 1 });
  return terms;
}

/** The plan's identity: definition, parameters and schedule together. */
export function hashPlanTerms(terms: AutomationPlanTerms): Hex {
  return keccak256(stringToHex(canonicalJson(terms))) as Hex;
}

/** Unix seconds at which occurrence `slot` opens. */
export function slotTime(terms: AutomationPlanTerms, slot: number): number {
  if (!Number.isSafeInteger(slot) || slot < 0 || slot >= terms.schedule.occurrences)
    return invalid("plan_slot_invalid", "slot is outside the schedule");
  return terms.schedule.startAt + slot * terms.schedule.every;
}

function referenceValue(
  reference: string,
  definition: AutomationDefinition,
  terms: AutomationPlanTerms,
  slot: number | null,
): unknown {
  const { schedule } = terms;
  switch (reference) {
    case "$plan.id":
      return terms.planId;
    case "$plan.account":
      return terms.account;
    case "$plan.startAt":
      return BigInt(schedule.startAt);
    case "$plan.endAt":
      return BigInt(schedule.endAt);
    case "$plan.every":
      return BigInt(schedule.every);
    case "$plan.grace":
      return BigInt(schedule.grace);
    case "$plan.occurrences":
      return BigInt(schedule.occurrences);
    case "$slot.index":
      return BigInt(slot as number);
    case "$slot.at":
      return BigInt(slotTime(terms, slot as number));
  }
  if (reference.startsWith("$contract.")) return definition.contracts[reference.slice(10)]?.address;
  const param = terms.params[reference.slice(7)];
  const type = definition.params[reference.slice(7)]?.type;
  return type !== undefined && uintBits(type) !== null ? BigInt(param as string) : param;
}

function argumentValue(
  argument: AutomationArgument,
  type: AutomationValueType,
  definition: AutomationDefinition,
  terms: AutomationPlanTerms,
  slot: number | null,
): unknown {
  const value =
    typeof argument === "string" && argument.startsWith("$")
      ? referenceValue(argument, definition, terms, slot)
      : uintBits(type) !== null
        ? BigInt(argument as string | number)
        : argument;
  const bits = uintBits(type);
  if (bits !== null && (typeof value !== "bigint" || value < 0n || value >= 1n << BigInt(bits)))
    return invalid("plan_call_unencodable", `a value does not fit ${type}`);
  return typeof value === "string" ? value.toLowerCase() : value;
}

function resolveCall(
  definition: AutomationDefinition,
  terms: AutomationPlanTerms,
  call: NormalizedAutomationCall,
  slot: number | null,
): ResolvedCall {
  const contract = definition.contracts[call.contract];
  if (!contract) return invalid("plan_invalid", "call names no declared contract");
  const fn = contractFunction(contract, call.function);
  const values = call.args.map((argument, index) =>
    argumentValue(argument, fn.inputs[index] as AutomationValueType, definition, terms, slot),
  );
  return Object.freeze({
    target: contract.address,
    value: call.value,
    data: encodeCall(contract, call.function, values),
  });
}

/** The exact calls of one operation: the setup, the cancellation, or one occurrence. */
export function resolveCalls(
  definition: AutomationDefinition,
  terms: AutomationPlanTerms,
  which: "setup" | "cancel" | Readonly<{ slot: number }>,
): readonly ResolvedCall[] {
  if (which === "setup" || which === "cancel")
    return Object.freeze(
      definition[which].map((call) => resolveCall(definition, terms, call, null)),
    );
  slotTime(terms, which.slot);
  return Object.freeze([resolveCall(definition, terms, definition.call, which.slot)]);
}

/** Operations the Grant must allow: every occurrence, plus setup and cancel when declared. */
export function planOperationCount(
  definition: AutomationDefinition,
  terms: AutomationPlanTerms,
): number {
  return (
    terms.schedule.occurrences +
    (definition.setup.length > 0 ? 1 : 0) +
    (definition.cancel.length > 0 ? 1 : 0)
  );
}

/**
 * The Grant policy the owner approves: exactly the declared contract
 * functions, valid from `validAfter` until the schedule ends, for at most the
 * plan's operations. A definition can never authorize a call it does not declare.
 */
export function derivePlanPolicy(
  definition: AutomationDefinition,
  terms: AutomationPlanTerms,
  validAfter: number,
): Readonly<GrantPolicy> {
  const allowed = new Map<string, { target: Address; selector: Hex; valueLimit: bigint }>();
  for (const call of [...definition.setup, definition.call, ...definition.cancel]) {
    const contract = definition.contracts[call.contract] as (typeof definition.contracts)[string];
    const { selector } = contractFunction(contract, call.function);
    const key = `${contract.address}:${selector}`;
    const value = BigInt(call.value);
    const existing = allowed.get(key);
    allowed.set(key, {
      target: contract.address,
      selector,
      valueLimit: existing && existing.valueLimit > value ? existing.valueLimit : value,
    });
  }
  const calls = [...allowed.entries()]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([, entry]) => ({
      target: entry.target,
      selector: entry.selector,
      valueLimit: entry.valueLimit.toString(),
      argumentEquals: [],
    }));
  return parseGrantPolicy({
    version: OAATH_GRANT_POLICY_VERSION,
    calls,
    validAfter,
    validUntil: terms.schedule.endAt - 1,
    perChainOperationLimit: { count: planOperationCount(definition, terms), intervalSeconds: null },
  });
}
