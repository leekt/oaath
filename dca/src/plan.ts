/**
 * The page's pure logic: which service definitions it offers, turning the
 * form into a plan request, and turning a plan's runs into per-buy rows.
 *
 * The service's loaded definitions are the one source of the market
 * (`token` and `dca` contracts), intervals and bounds; nothing here repeats
 * an address.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { AutomationDefinition, CreatePlan, Run } from "@oaath/automation";

export const SELL_DECIMALS = 6;
export const BUY_DECIMALS = 18;
/** The executor's oracle bound: at most 3% below the feed price, fee included. */
export const MAX_SLIPPAGE_BPS = "300";
/** Time to approve in the popup before the first buy's window opens. */
export const START_DELAY_SECONDS = 180;

export interface DcaOption {
  readonly id: string;
  readonly name: string;
  readonly every: number;
  readonly grace: number;
  readonly minBuys: number;
  readonly maxBuys: number;
  /** Inclusive budget cap in sell-token base units, or null when unbounded. */
  readonly maxBudget: bigint | null;
  readonly sellToken: `0x${string}`;
  readonly executor: `0x${string}`;
}

export class PlanInputError extends Error {
  constructor(readonly code: "amount_invalid" | "buys_invalid" | "budget_too_large") {
    super(code);
    this.name = "PlanInputError";
  }
}

/** The DCA definitions the service offers on this chain, shortest interval first. */
export function dcaOptions(
  definitions: readonly AutomationDefinition[],
  prefix: string,
  chainId: number,
): DcaOption[] {
  return definitions
    .filter(
      (definition) =>
        definition.id.startsWith(prefix) &&
        definition.chainId === chainId &&
        definition.contracts.token !== undefined &&
        definition.contracts.dca !== undefined &&
        definition.params.budget !== undefined,
    )
    .map((definition) => ({
      id: definition.id,
      name: definition.name,
      every: definition.schedule.every,
      grace: definition.schedule.grace,
      minBuys: definition.schedule.count.min,
      maxBuys: definition.schedule.count.max,
      maxBudget:
        definition.params.budget?.max === undefined ? null : BigInt(definition.params.budget.max),
      sellToken: definition.contracts.token?.address as `0x${string}`,
      executor: definition.contracts.dca?.address as `0x${string}`,
    }))
    .sort((a, b) => a.every - b.every);
}

/** A positive decimal amount in base units, or null. */
export function parseAmount(text: string, decimals: number): bigint | null {
  const match = /^([0-9]{1,12})(?:\.([0-9]+))?$/u.exec(text.trim());
  if (!match) return null;
  const fraction = match[2] ?? "";
  if (fraction.length > decimals) return null;
  const value = BigInt(`${match[1]}${fraction.padEnd(decimals, "0")}`);
  return value > 0n ? value : null;
}

export function formatUnits(value: bigint, decimals: number, maxFraction = 6): string {
  const scale = 10n ** BigInt(decimals);
  const fraction = (value % scale)
    .toString()
    .padStart(decimals, "0")
    .slice(0, maxFraction)
    .replace(/0+$/u, "");
  return `${value / scale}${fraction ? `.${fraction}` : ""}`;
}

export function intervalLabel(seconds: number): string {
  for (const [unit, size] of [
    ["day", 86_400],
    ["hour", 3_600],
    ["minute", 60],
  ] as const) {
    if (seconds % size === 0) {
      const count = seconds / size;
      return count === 1 ? `1 ${unit}` : `${count} ${unit}s`;
    }
  }
  return `${seconds} seconds`;
}

/**
 * The plan the form asks for: `buys` purchases of `amount` each. The budget is
 * their product, so the executor's even split buys exactly `amount` per slot.
 */
export function planRequest(
  option: DcaOption,
  amount: string,
  buys: number,
  now: number,
  idempotencyKey: string,
): CreatePlan {
  const perBuy = parseAmount(amount, SELL_DECIMALS);
  if (perBuy === null) throw new PlanInputError("amount_invalid");
  if (!Number.isSafeInteger(buys) || buys < option.minBuys || buys > option.maxBuys)
    throw new PlanInputError("buys_invalid");
  const budget = perBuy * BigInt(buys);
  if (option.maxBudget !== null && budget > option.maxBudget)
    throw new PlanInputError("budget_too_large");
  return {
    automation: option.id,
    params: { budget: budget.toString(), maxSlippageBps: MAX_SLIPPAGE_BPS },
    occurrences: buys,
    startAt: now + START_DELAY_SECONDS,
    idempotencyKey,
  };
}

export type Tone = "pending" | "active" | "done" | "failed";

export interface RunRow {
  readonly key: string;
  readonly label: string;
  readonly status: string;
  readonly tone: Tone;
  /** Unix seconds the run opens. */
  readonly at: number;
  readonly transactionUrl: string | null;
}

const STATUS: Readonly<Record<Run["status"], readonly [string, Tone]>> = {
  due: ["Due", "active"],
  claimed: ["Preparing", "active"],
  prepared: ["Preparing", "active"],
  submitted: ["Submitted", "active"],
  observed: ["Included", "done"],
  finalized: ["Finalized", "done"],
  failed: ["Failed", "failed"],
  skipped: ["Missed its window", "failed"],
};

/**
 * One row for the setup and each buy, in order. A buy the service has not
 * scheduled yet shows as upcoming at its slot time.
 */
export function runRows(
  runs: readonly Run[],
  schedule: Readonly<{ startAt: number; every: number; occurrences: number }>,
  explorerTxUrl: string | null,
): RunRow[] {
  const row = (run: Run | undefined, key: string, label: string, at: number): RunRow => {
    const [status, tone] = run ? STATUS[run.status] : (["Upcoming", "pending"] as const);
    return {
      key,
      label,
      status,
      tone,
      at: run?.scheduledAt ?? at,
      transactionUrl:
        run?.transactionHash && explorerTxUrl ? `${explorerTxUrl}${run.transactionHash}` : null,
    };
  };
  const setup = runs.find((run) => run.kind === "setup");
  const rows = [row(setup, "setup", "Setup: mint test tUSD, approve, open plan", schedule.startAt)];
  for (let slot = 0; slot < schedule.occurrences; slot += 1) {
    rows.push(
      row(
        runs.find((run) => run.kind === "occurrence" && run.slot === slot),
        `buy-${slot}`,
        `Buy ${slot + 1} of ${schedule.occurrences}`,
        schedule.startAt + slot * schedule.every,
      ),
    );
  }
  const cancel = runs.find((run) => run.kind === "cancel");
  if (cancel) rows.push(row(cancel, "cancel", "Cancel: close plan, clear allowance", 0));
  return rows;
}

const word = (address: string) => address.slice(2).toLowerCase().padStart(64, "0");

/** `eth_call` data for `balanceOf(account)`. */
export const balanceOfData = (account: string) => `0x70a08231${word(account)}`;
/** `eth_call` data for the executor's `buyToken()`. */
export const BUY_TOKEN_DATA = "0xa4821719";

/** The address in an ABI-encoded single-address return value. */
export function decodeAddress(result: unknown): `0x${string}` | null {
  if (typeof result !== "string" || !/^0x0{24}[0-9a-fA-F]{40}$/u.test(result)) return null;
  return `0x${result.slice(26).toLowerCase()}`;
}

/** A uint256 return value. */
export function decodeUint(result: unknown): bigint | null {
  if (typeof result !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(result)) return null;
  return BigInt(result);
}

/** The one call the app's relay sends: `token.mint(recipient, amount)`, zero value. */
export function mintCall(token: string, recipient: string, amount: string) {
  const data = `0x40c10f19${word(recipient)}${BigInt(amount).toString(16).padStart(64, "0")}`;
  return { to: token as `0x${string}`, data: data as `0x${string}` } as const;
}
