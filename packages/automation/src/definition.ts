/**
 * The one owner of the automation definition schema.
 *
 * An automation is declarative data, of one of two kinds. An on-demand
 * automation is only a call list (target, selector, value ceiling), chains and
 * limits: the application submits exact calls later, each checked against the
 * approved list. A scheduled automation declares the contracts it calls, a bounded
 * schedule, typed user parameters, and the calls themselves with a minimal
 * reference language. There is no scripting: an argument is a literal or one
 * `$` reference, nothing else.
 *
 * ```text
 * $plan.id $plan.account $plan.startAt $plan.endAt $plan.every $plan.grace
 * $plan.occurrences $slot.index $slot.at $param.<name> $contract.<name>
 * ```
 *
 * A definition authorizes nothing by itself. A plan freezes one definition,
 * its parameters and schedule (see `./plan.ts`), and the permission derived
 * from them is exactly the set of declared contract functions.
 *
 * @author taek <leekt216@gmail.com>
 */
import { encodeFunctionData, keccak256, stringToHex } from "cetane/utils";
import { AutomationError } from "./error.js";

export const AUTOMATION_DEFINITION_VERSION = "oaath.automation/v1" as const;

export type Address = `0x${string}`;
export type Hex = `0x${string}`;

/** The ABI types a declared function may take: static elementary types only. */
export type AutomationValueType = "address" | "bool" | "bytes32" | `uint${number}`;

export interface AutomationAbiParameter {
  readonly name?: string;
  readonly type: string;
}

/** A function ABI item. Other item kinds are accepted and ignored. */
export interface AutomationAbiItem {
  readonly type: string;
  readonly name?: string;
  readonly inputs?: readonly AutomationAbiParameter[];
  readonly outputs?: readonly AutomationAbiParameter[];
  readonly stateMutability?: string;
}

export interface AutomationContract {
  readonly address: Address;
  readonly abi: readonly AutomationAbiItem[];
}

export interface AutomationParam {
  readonly type: AutomationValueType;
  /** Shown in the consent review. */
  readonly label?: string;
  /** Display hint for unsigned amounts; the value itself is in base units. */
  readonly decimals?: number;
  /** Inclusive canonical decimal bounds for unsigned parameters. */
  readonly min?: string;
  readonly max?: string;
}

/** A literal, or a string starting with `$` that names one reference. */
export type AutomationArgument = string | number | boolean;

export interface AutomationCall {
  readonly contract: string;
  readonly function: string;
  readonly args?: readonly AutomationArgument[];
  /** Canonical decimal native value, at most `limits.valuePerCall`. Defaults to "0". */
  readonly value?: string;
}

export interface AutomationSchedule {
  /** Seconds, or `<n>s`, `<n>m`, `<n>h`, `<n>d`. At least one minute. */
  readonly every: number | string;
  /** A fixed number of occurrences, or the plan chooses 1..max. */
  readonly count: number | Readonly<{ min?: number; max: number }>;
  /** How long after its time an occurrence may still run. Defaults to min(every, 15m). */
  readonly grace?: number | string;
}

export interface ScheduledAutomationDefinitionInput {
  readonly kind?: "scheduled";
  readonly id: string;
  readonly name: string;
  readonly chainId: number;
  readonly contracts: Readonly<Record<string, AutomationContract>>;
  readonly params?: Readonly<Record<string, AutomationParam>>;
  readonly schedule: AutomationSchedule;
  /** Calls of one operation run once, before the first occurrence. */
  readonly setup?: readonly AutomationCall[];
  /** The call each occurrence runs. */
  readonly call: AutomationCall;
  /** Calls of one operation run once when a plan is cancelled. */
  readonly cancel?: readonly AutomationCall[];
  readonly limits?: Readonly<{ valuePerCall?: string }>;
}

export interface AutomationFunction {
  readonly name: string;
  readonly inputs: readonly AutomationValueType[];
  readonly selector: Hex;
}

export interface NormalizedAutomationCall {
  readonly contract: string;
  readonly function: string;
  readonly args: readonly AutomationArgument[];
  readonly value: string;
}

/** A validated, frozen scheduled definition. Durations are normalized to seconds. */
export interface ScheduledAutomationDefinition {
  readonly version: typeof AUTOMATION_DEFINITION_VERSION;
  readonly kind: "scheduled";
  readonly id: string;
  readonly name: string;
  readonly chainId: number;
  readonly contracts: Readonly<Record<string, AutomationContract>>;
  readonly params: Readonly<Record<string, AutomationParam>>;
  readonly schedule: Readonly<{
    every: number;
    count: Readonly<{ min: number; max: number }>;
    grace: number;
  }>;
  readonly setup: readonly NormalizedAutomationCall[];
  readonly call: NormalizedAutomationCall;
  readonly cancel: readonly NormalizedAutomationCall[];
  readonly limits: Readonly<{ valuePerCall: string }>;
}

/** One call an on-demand automation allows: a target, a selector and a value ceiling. */
export interface OnDemandCall {
  readonly target: Address;
  /** 4-byte selector; `0x00000000` is a call with empty calldata (a plain transfer). */
  readonly selector: Hex;
  /** Canonical decimal native value ceiling per call. Defaults to "0". */
  readonly valueLimit?: string;
}

export interface OnDemandLimits {
  /**
   * Operations per chain: `count` per window of `intervalSeconds` (86400 for a
   * daily limit, enforced by the Kernel rate-limit policy), or a lifetime cap
   * when `intervalSeconds` is null.
   */
  readonly operationsPerChain: Readonly<{ count: number; intervalSeconds: number | null }>;
  /** Longest validity a plan may request: seconds, or `<n>s|m|h|d`. */
  readonly maxValidFor: number | string;
}

/**
 * An automation with no schedule: the application submits exact calls on
 * demand, each one checked against the approved call list before it is sent.
 */
export interface OnDemandAutomationDefinitionInput {
  readonly version?: typeof AUTOMATION_DEFINITION_VERSION;
  readonly kind: "on-demand";
  readonly id: string;
  readonly name: string;
  readonly chains: readonly number[];
  readonly calls: readonly OnDemandCall[];
  readonly limits: OnDemandLimits;
}

export interface OnDemandAutomationDefinition {
  readonly version: typeof AUTOMATION_DEFINITION_VERSION;
  readonly kind: "on-demand";
  readonly id: string;
  readonly name: string;
  /** Ascending, unique. */
  readonly chains: readonly number[];
  /** Unique, sorted by `target:selector`, lowercase. */
  readonly calls: readonly Readonly<Required<OnDemandCall>>[];
  readonly limits: Readonly<{
    operationsPerChain: Readonly<{ count: number; intervalSeconds: number | null }>;
    maxValidFor: number;
  }>;
}

export type AutomationDefinitionInput =
  | ScheduledAutomationDefinitionInput
  | OnDemandAutomationDefinitionInput;
/** One validated definition; `kind` tells a scheduled automation from an on-demand one. */
export type AutomationDefinition = ScheduledAutomationDefinition | OnDemandAutomationDefinition;

const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/u;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/u;
const DURATION = /^([1-9][0-9]{0,8})([smhd])$/u;
const UNIT = { s: 1, m: 60, h: 3600, d: 86400 } as const;
const MAX_OCCURRENCES = 1000;
const MAX_CALLS = 8;
const MAX_ON_DEMAND_CALLS = 32;
const MAX_CHAINS = 32;
const MAX_UINT48 = 2 ** 48 - 1;
const MAX_UINT256 = (1n << 256n) - 1n;
/** Ten years: every schedule must end inside a representable Kernel window. */
const MAX_SPAN_SECONDS = 10 * 365 * 86400;

function fail(message: string): never {
  throw new AutomationError("automation_definition_invalid", 0, message);
}

function plainRecord(value: unknown, label: string): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    return fail(`${label} must be a plain object`);
  return value as Record<string, unknown>;
}

function exactKeys(
  record: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  for (const key of Object.keys(record)) {
    if (!required.includes(key) && !optional.includes(key))
      fail(`${label} has unknown field ${key}`);
  }
  for (const key of required) {
    if (record[key] === undefined) fail(`${label} needs ${key}`);
  }
}

export function isValueType(type: string): type is AutomationValueType {
  if (type === "address" || type === "bool" || type === "bytes32") return true;
  const match = /^uint([0-9]{1,3})$/u.exec(type);
  if (!match) return false;
  const bits = Number(match[1]);
  return bits >= 8 && bits <= 256 && bits % 8 === 0;
}

export function uintBits(type: AutomationValueType): number | null {
  return type.startsWith("uint") ? Number(type.slice(4)) : null;
}

function duration(value: unknown, label: string): number {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 1) fail(`${label} must be positive seconds`);
    return value;
  }
  const match = typeof value === "string" ? DURATION.exec(value) : null;
  if (!match) return fail(`${label} must be seconds or <n>s|m|h|d`);
  return Number(match[1]) * UNIT[match[2] as keyof typeof UNIT];
}

function decimal(value: unknown, label: string): string {
  if (typeof value !== "string" || !DECIMAL.test(value) || BigInt(value) > MAX_UINT256)
    return fail(`${label} must be a canonical decimal uint256`);
  return value;
}

/** The canonical signature and selector of one elementary-typed function. */
export function functionSelector(name: string, inputs: readonly string[]): Hex {
  return keccak256(stringToHex(`${name}(${inputs.join(",")})`)).slice(0, 10) as Hex;
}

/** The unique declared function `name` of a contract; overloads are refused. */
export function contractFunction(contract: AutomationContract, name: string): AutomationFunction {
  const items = contract.abi.filter((item) => item.type === "function" && item.name === name);
  if (items.length !== 1) return fail(`function ${name} must be declared exactly once`);
  const inputs = (items[0]?.inputs ?? []).map((input) => input.type);
  for (const type of inputs) {
    if (!isValueType(type)) fail(`function ${name} takes unsupported type ${type}`);
  }
  return Object.freeze({
    name,
    inputs: Object.freeze(inputs as AutomationValueType[]),
    selector: functionSelector(name, inputs),
  });
}

const PLAN_REFERENCES: Readonly<Record<string, "bytes32" | "address" | "uint">> = Object.freeze({
  "$plan.id": "bytes32",
  "$plan.account": "address",
  "$plan.startAt": "uint",
  "$plan.endAt": "uint",
  "$plan.every": "uint",
  "$plan.grace": "uint",
  "$plan.occurrences": "uint",
  "$slot.index": "uint",
  "$slot.at": "uint",
});

/** What a reference produces: a fixed kind, or a parameter's declared type. */
function referenceKind(
  reference: string,
  definition: Pick<ScheduledAutomationDefinition, "contracts" | "params">,
  inSlot: boolean,
): "bytes32" | "address" | "uint" | "bool" | AutomationValueType {
  if (reference.startsWith("$slot.") && !inSlot)
    return fail(`${reference} is only available in the occurrence call`);
  const fixed = PLAN_REFERENCES[reference];
  if (fixed) return fixed;
  if (reference.startsWith("$contract.")) {
    if (!Object.hasOwn(definition.contracts, reference.slice(10)))
      fail(`${reference} names no declared contract`);
    return "address";
  }
  if (reference.startsWith("$param.")) {
    const param = definition.params[reference.slice(7)];
    if (!param) return fail(`${reference} names no declared parameter`);
    return param.type;
  }
  return fail(`${reference} is not a reference`);
}

function argumentFits(
  argument: AutomationArgument,
  type: AutomationValueType,
  definition: Pick<ScheduledAutomationDefinition, "contracts" | "params">,
  inSlot: boolean,
  label: string,
): void {
  if (typeof argument === "string" && argument.startsWith("$")) {
    const kind = referenceKind(argument, definition, inSlot);
    const fits =
      kind === type ||
      ((kind === "uint" || uintBits(kind as AutomationValueType) !== null) &&
        uintBits(type) !== null);
    if (!fits) fail(`${label} ${argument} does not fit ${type}`);
    return;
  }
  const bits = uintBits(type);
  if (bits !== null) {
    const value =
      typeof argument === "number" && Number.isSafeInteger(argument) && argument >= 0
        ? String(argument)
        : argument;
    if (typeof value !== "string" || !DECIMAL.test(value) || BigInt(value) >= 1n << BigInt(bits))
      fail(`${label} literal does not fit ${type}`);
    return;
  }
  if (type === "bool" && typeof argument === "boolean") return;
  if (type === "address" && typeof argument === "string" && ADDRESS.test(argument)) return;
  if (type === "bytes32" && typeof argument === "string" && /^0x[0-9a-fA-F]{64}$/u.test(argument))
    return;
  fail(`${label} literal does not fit ${type}`);
}

function call(
  value: unknown,
  definition: Pick<ScheduledAutomationDefinition, "contracts" | "params">,
  valueLimit: bigint,
  inSlot: boolean,
  label: string,
): NormalizedAutomationCall {
  const record = plainRecord(value, label);
  exactKeys(record, ["contract", "function"], ["args", "value"], label);
  const contract = definition.contracts[record.contract as string];
  if (typeof record.contract !== "string" || !contract)
    return fail(`${label} names no declared contract`);
  if (typeof record.function !== "string") return fail(`${label} function must be a name`);
  const fn = contractFunction(contract, record.function);
  const args = record.args ?? [];
  if (!Array.isArray(args) || args.length !== fn.inputs.length)
    return fail(`${label} must pass exactly ${fn.inputs.length} arguments`);
  args.forEach((argument: unknown, index) => {
    if (!["string", "number", "boolean"].includes(typeof argument))
      fail(`${label} argument ${index} is not a literal or reference`);
    argumentFits(
      argument as AutomationArgument,
      fn.inputs[index] as AutomationValueType,
      definition,
      inSlot,
      `${label} argument ${index}`,
    );
  });
  const callValue = record.value === undefined ? "0" : decimal(record.value, `${label} value`);
  if (BigInt(callValue) > valueLimit) fail(`${label} value exceeds limits.valuePerCall`);
  return Object.freeze({
    contract: record.contract,
    function: record.function,
    args: Object.freeze([...(args as AutomationArgument[])]),
    value: callValue,
  });
}

function calls(
  value: unknown,
  definition: Pick<ScheduledAutomationDefinition, "contracts" | "params">,
  valueLimit: bigint,
  label: string,
): readonly NormalizedAutomationCall[] {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_CALLS)
    return fail(`${label} must hold 1 to ${MAX_CALLS} calls`);
  return Object.freeze(
    value.map((entry, index) => call(entry, definition, valueLimit, false, `${label} ${index}`)),
  );
}

function identity(record: Record<string, unknown>): void {
  if (record.version !== undefined && record.version !== AUTOMATION_DEFINITION_VERSION)
    fail("automation version is unsupported");
  if (typeof record.id !== "string" || !ID.test(record.id)) fail("automation id is invalid");
  if (typeof record.name !== "string" || record.name.length < 1 || record.name.length > 80)
    fail("automation name must be 1 to 80 characters");
}

function positive(value: unknown, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    fail(`${label} must be an integer from 1 to ${maximum}`);
  return value as number;
}

function defineOnDemand(record: Record<string, unknown>): OnDemandAutomationDefinition {
  exactKeys(record, ["kind", "id", "name", "chains", "calls", "limits"], ["version"], "automation");
  identity(record);
  const chainList = record.chains;
  if (!Array.isArray(chainList) || chainList.length < 1 || chainList.length > MAX_CHAINS)
    fail(`chains must name 1 to ${MAX_CHAINS} chains`);
  const chains = (chainList as unknown[]).map((chain) =>
    positive(chain, Number.MAX_SAFE_INTEGER, "chain id"),
  );
  if (new Set(chains).size !== chains.length) fail("chains must be unique");
  const callList = record.calls;
  if (!Array.isArray(callList) || callList.length < 1 || callList.length > MAX_ON_DEMAND_CALLS)
    fail(`calls must hold 1 to ${MAX_ON_DEMAND_CALLS} calls`);
  const calls = (callList as unknown[]).map((value, index) => {
    const entry = plainRecord(value, `call ${index}`);
    exactKeys(entry, ["target", "selector"], ["valueLimit"], `call ${index}`);
    if (typeof entry.target !== "string" || !ADDRESS.test(entry.target))
      fail(`call ${index} target is invalid`);
    if (typeof entry.selector !== "string" || !/^0x[0-9a-fA-F]{8}$/u.test(entry.selector))
      fail(`call ${index} selector must be 4 bytes`);
    return Object.freeze({
      target: (entry.target as string).toLowerCase() as Address,
      selector: (entry.selector as string).toLowerCase() as Hex,
      valueLimit:
        entry.valueLimit === undefined
          ? "0"
          : decimal(entry.valueLimit, `call ${index} valueLimit`),
    });
  });
  const key = (call: { target: string; selector: string }) => `${call.target}:${call.selector}`;
  calls.sort((a, b) => (key(a) < key(b) ? -1 : 1));
  if (new Set(calls.map(key)).size !== calls.length)
    fail("calls must be unique by target and selector");
  const limits = plainRecord(record.limits, "limits");
  exactKeys(limits, ["operationsPerChain", "maxValidFor"], [], "limits");
  const operations = plainRecord(limits.operationsPerChain, "operationsPerChain");
  exactKeys(operations, ["count", "intervalSeconds"], [], "operationsPerChain");
  const operationsPerChain = Object.freeze({
    count: positive(operations.count, MAX_UINT48, "operationsPerChain count"),
    intervalSeconds:
      operations.intervalSeconds === null
        ? null
        : positive(operations.intervalSeconds, MAX_UINT48, "operationsPerChain intervalSeconds"),
  });
  const maxValidFor = duration(limits.maxValidFor, "maxValidFor");
  if (maxValidFor > MAX_SPAN_SECONDS) fail("maxValidFor spans too long");
  return Object.freeze({
    version: AUTOMATION_DEFINITION_VERSION,
    kind: "on-demand",
    id: record.id as string,
    name: record.name as string,
    chains: Object.freeze(chains.sort((a, b) => a - b)),
    calls: Object.freeze(calls),
    limits: Object.freeze({ operationsPerChain, maxValidFor }),
  });
}

/**
 * Validates and freezes one automation definition, either kind. Every
 * declared scheduled call is checked against its contract's ABI, and every
 * argument against its parameter type, before any plan can use it.
 */
export function defineAutomation(
  input: ScheduledAutomationDefinitionInput,
): ScheduledAutomationDefinition;
export function defineAutomation(
  input: OnDemandAutomationDefinitionInput,
): OnDemandAutomationDefinition;
export function defineAutomation(input: AutomationDefinitionInput): AutomationDefinition;
export function defineAutomation(input: AutomationDefinitionInput): AutomationDefinition {
  const record = plainRecord(input, "automation");
  if (record.kind === "on-demand") return defineOnDemand(record);
  if (record.kind !== undefined && record.kind !== "scheduled")
    fail("automation kind is unsupported");
  const optional = ["version", "kind", "params", "setup", "cancel", "limits"];
  exactKeys(
    record,
    ["id", "name", "chainId", "contracts", "schedule", "call"],
    optional,
    "automation",
  );
  identity(record);
  if (
    typeof record.chainId !== "number" ||
    !Number.isSafeInteger(record.chainId) ||
    record.chainId < 1
  )
    fail("automation chainId must be a positive integer");

  const contractEntries = Object.entries(plainRecord(record.contracts, "contracts"));
  if (contractEntries.length < 1 || contractEntries.length > 8)
    fail("contracts must declare 1 to 8 contracts");
  const contracts: Record<string, AutomationContract> = {};
  for (const [name, value] of contractEntries) {
    if (!NAME.test(name)) fail(`contract name ${name} is invalid`);
    const contract = plainRecord(value, `contract ${name}`);
    exactKeys(contract, ["address", "abi"], [], `contract ${name}`);
    if (typeof contract.address !== "string" || !ADDRESS.test(contract.address))
      fail(`contract ${name} address is invalid`);
    if (!Array.isArray(contract.abi)) fail(`contract ${name} abi must be an array`);
    contracts[name] = Object.freeze({
      address: (contract.address as string).toLowerCase() as Address,
      abi: Object.freeze(structuredClone(contract.abi) as AutomationAbiItem[]),
    });
  }

  const params: Record<string, AutomationParam> = {};
  for (const [name, value] of Object.entries(plainRecord(record.params ?? {}, "params"))) {
    if (!NAME.test(name)) fail(`parameter name ${name} is invalid`);
    const param = plainRecord(value, `parameter ${name}`);
    exactKeys(param, ["type"], ["label", "decimals", "min", "max"], `parameter ${name}`);
    if (typeof param.type !== "string" || !isValueType(param.type))
      fail(`parameter ${name} type is unsupported`);
    const bits = uintBits(param.type as AutomationValueType);
    if ((param.min !== undefined || param.max !== undefined) && bits === null)
      fail(`parameter ${name} bounds need an unsigned type`);
    if (param.label !== undefined && (typeof param.label !== "string" || param.label.length > 80))
      fail(`parameter ${name} label is invalid`);
    if (
      param.decimals !== undefined &&
      (!Number.isSafeInteger(param.decimals) ||
        (param.decimals as number) < 0 ||
        (param.decimals as number) > 36)
    )
      fail(`parameter ${name} decimals is invalid`);
    const min = param.min === undefined ? undefined : decimal(param.min, `parameter ${name} min`);
    const max = param.max === undefined ? undefined : decimal(param.max, `parameter ${name} max`);
    if (bits !== null && max !== undefined && BigInt(max) >= 1n << BigInt(bits))
      fail(`parameter ${name} max does not fit ${param.type}`);
    if (min !== undefined && max !== undefined && BigInt(min) > BigInt(max))
      fail(`parameter ${name} bounds are inverted`);
    params[name] = Object.freeze({
      type: param.type as AutomationValueType,
      ...(param.label === undefined ? {} : { label: param.label as string }),
      ...(param.decimals === undefined ? {} : { decimals: param.decimals as number }),
      ...(min === undefined ? {} : { min }),
      ...(max === undefined ? {} : { max }),
    });
  }

  const schedule = plainRecord(record.schedule, "schedule");
  exactKeys(schedule, ["every", "count"], ["grace"], "schedule");
  const every = duration(schedule.every, "schedule every");
  if (every < 60) fail("schedule every must be at least one minute");
  const count =
    typeof schedule.count === "number"
      ? { min: schedule.count, max: schedule.count }
      : (() => {
          const range = plainRecord(schedule.count, "schedule count");
          exactKeys(range, ["max"], ["min"], "schedule count");
          return { min: (range.min ?? 1) as number, max: range.max as number };
        })();
  if (
    !Number.isSafeInteger(count.min) ||
    !Number.isSafeInteger(count.max) ||
    count.min < 1 ||
    count.min > count.max ||
    count.max > MAX_OCCURRENCES
  )
    fail(`schedule count must be 1 to ${MAX_OCCURRENCES}`);
  const grace =
    schedule.grace === undefined
      ? Math.min(every, 900)
      : duration(schedule.grace, "schedule grace");
  if (grace > every) fail("schedule grace must not exceed every");
  if ((count.max - 1) * every + grace > MAX_SPAN_SECONDS) fail("schedule spans too long");

  const limits = plainRecord(record.limits ?? {}, "limits");
  exactKeys(limits, [], ["valuePerCall"], "limits");
  const valuePerCall =
    limits.valuePerCall === undefined ? "0" : decimal(limits.valuePerCall, "valuePerCall");
  const shape = { contracts, params };
  const definition: ScheduledAutomationDefinition = {
    version: AUTOMATION_DEFINITION_VERSION,
    kind: "scheduled",
    id: record.id as string,
    name: record.name as string,
    chainId: record.chainId as number,
    contracts: Object.freeze(contracts),
    params: Object.freeze(params),
    schedule: Object.freeze({ every, count: Object.freeze(count), grace }),
    setup: calls(record.setup, shape, BigInt(valuePerCall), "setup"),
    call: call(record.call, shape, BigInt(valuePerCall), true, "call"),
    cancel: calls(record.cancel, shape, BigInt(valuePerCall), "cancel"),
    limits: Object.freeze({ valuePerCall }),
  };
  return Object.freeze(definition);
}

/** Re-validates a stored or transported definition through the same owner. */
export function parseAutomation(value: unknown): AutomationDefinition {
  return defineAutomation(value as AutomationDefinitionInput);
}

/** Deterministic JSON: object keys sorted, arrays in order. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** The definition's identity: any edit makes a different automation for new plans. */
export function hashAutomation(definition: AutomationDefinition): Hex {
  return keccak256(stringToHex(canonicalJson(definition))) as Hex;
}

/** Encodes one call's calldata from already-resolved argument values. */
export function encodeCall(
  contract: AutomationContract,
  name: string,
  values: readonly unknown[],
): Hex {
  const fn = contractFunction(contract, name);
  const abi = [
    {
      type: "function",
      name,
      stateMutability: "nonpayable",
      inputs: fn.inputs.map((type, index) => ({ name: `a${index}`, type })),
      outputs: [],
    },
  ];
  return encodeFunctionData({ abi, functionName: name, args: values } as never) as Hex;
}
