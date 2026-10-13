/**
 * The run executor: claims one open run at a time with a lease and drives it
 * through exactly one Operation.
 *
 * ```text
 * state and owner      run.status, by this module (op_hash/op_nonce: the journal adapter)
 *                      due -> claimed -> prepared -> submitted -> observed -> finalized
 *                      terminal: finalized | failed | skipped
 * plan effects         setup observed included and successful (or finalized):
 *                      authorized -> active; setup failed (even after inclusion):
 *                      authorized|active|paused -> failed
 * persisted evidence   calls before send; op hash + nonce journaled before any
 *                      signature or send (see ./store.ts); transaction hash on inclusion
 * resource occupied?   one open run per (plan, lane) (unique index), so one
 *                      unresolved operation per (grantId, chainId, lane); each run
 *                      sends and observes only on the lane stored on it
 * retry positively     send: only while op_hash is null (never journaled) or the SDK
 *   safe?              proved the identity abandoned before submission;
 *                      observation: always, and it submits nothing
 * forbidden            sending for a run that has an op_hash; resending after a
 *                      timeout, missing receipt, drop or unreadable observation
 * crash/reload         leases expire; any replica resumes from PostgreSQL; every
 *                      write is fenced by the claim's generation
 * cleanup owner        the claiming replica closes its Grant handle; a failed close
 *                      never changes the run's outcome
 * ```
 *
 * @author taek <leekt216@gmail.com>
 */
import { type ResolvedCall, resolveCalls } from "@oaath/automation";
import { BudgetError } from "./budget.js";
import type { ChainEndpoints } from "./config.js";
import { type PlanRow, readPlan, type ServiceContext } from "./context.js";
import type { Pool } from "./db.js";
import { openGrant } from "./grant.js";

export const LEASE_SECONDS = 120;
const MAX_SEND_ATTEMPTS = 3;

export interface RunRow {
  readonly plan_id: string;
  readonly run_key: string;
  readonly kind: "setup" | "occurrence" | "cancel";
  readonly slot: number | null;
  /** The Kernel nonce lane the scheduler assigned; 0 is the default lane. */
  readonly lane: number;
  readonly scheduled_at: number;
  readonly closes_at: number | null;
  readonly status: string;
  readonly calls: readonly ResolvedCall[] | null;
  readonly op_hash: `0x${string}` | null;
  readonly op_nonce: string | null;
  readonly attempts: number;
  readonly observations: number;
  readonly generation: number;
}

export type Observation = Readonly<{
  status: "finalized" | "dropped" | "superseded" | "abandoned" | "pending" | "unreadable";
  transactionHash: `0x${string}` | null;
  /**
   * The UserOperation's outcome while the SDK journal records it included but
   * not yet final; absent otherwise. The same evidence the SDK requires before
   * an explicit lane may run beside the install.
   */
  inclusion?: "success" | "reverted";
  /** Finalized execution facts, only for `finalized`. */
  execution: Readonly<{
    sender: string;
    calls: readonly Readonly<{ target: string; value: string; data: string }>[];
    outcome: "success" | "reverted";
  }> | null;
}>;

/** A run's SDK lane: absent for the default lane, else the run's own key and label. */
export type RunLane = Readonly<{ id: string; nonceKey: bigint }> | null;

export function runLane(run: Pick<RunRow, "run_key" | "lane">): RunLane {
  return run.lane === 0 ? null : Object.freeze({ id: run.run_key, nonceKey: BigInt(run.lane) });
}

/** The one boundary to OAAth for a run: start calls, or observe a journaled operation, on the run's lane. */
export interface OperationGateway {
  send(calls: readonly ResolvedCall[], lane: RunLane): Promise<`0x${string}`>;
  /** null: the journal holds no such operation (unreadable, never "absent"). */
  observe(id: `0x${string}`, lane: RunLane): Promise<Observation | null>;
  close(): Promise<void>;
}

export type OpenGateway = (plan: PlanRow) => Promise<OperationGateway>;

/**
 * The ERC-7677 payer for a chain, or null when operations are self-funded. A
 * configured API key travels in the context (`{ apiKey }`), as paymaster-rs
 * accepts it; otherwise the context is `{}`.
 */
export function paymasterPayer(endpoints: ChainEndpoints | undefined) {
  if (!endpoints || endpoints.paymasterUrl === null) return null;
  return {
    kind: "paymaster-service" as const,
    url: endpoints.paymasterUrl,
    context: endpoints.paymasterApiKey === null ? {} : { apiKey: endpoints.paymasterApiKey },
  };
}

/** The default gateway: the plan's Grant handle over the budgeted chain ports. */
export function grantGateway(context: ServiceContext): OpenGateway {
  return async (plan) => {
    const opened = await openGrant(context, plan);
    const chain = plan.terms.chainId;
    const payer = paymasterPayer(context.config.chains.get(chain));
    return {
      async send(calls, lane) {
        const operation = await opened.grant.sendCalls({
          chain,
          calls: calls.map((call) => ({ target: call.target, value: call.value, data: call.data })),
          ...(payer === null ? {} : { payer }),
          ...(lane === null ? {} : { lane }),
        });
        await operation.close().catch(() => undefined);
        return operation.id;
      },
      async observe(id, lane) {
        const operation = await opened.grant.getOperation({
          chain,
          id,
          ...(lane === null ? {} : { lane }),
        });
        if (operation === null) return null;
        try {
          const outcome = await operation.observe();
          const execution = outcome.status === "finalized" ? await operation.execution() : null;
          return {
            status: outcome.status,
            transactionHash: outcome.transactionHash,
            ...(outcome.state === "included" && outcome.outcome !== null
              ? { inclusion: outcome.outcome }
              : {}),
            execution:
              execution === null
                ? null
                : { sender: execution.sender, calls: execution.calls, outcome: execution.outcome },
          };
        } finally {
          await operation.close().catch(() => undefined);
        }
      },
      close: opened.close,
    };
  };
}

/** Claims the next open run whose time has come, fencing it with a new generation. */
export async function claimRun(context: ServiceContext): Promise<RunRow | null> {
  const now = context.now();
  const result = await context.pool.query(
    `WITH next AS (
       SELECT plan_id, run_key FROM automation_runs
       WHERE status IN ('due','claimed','prepared','submitted','observed')
         AND next_attempt_at<=$1 AND lease_until<=$1
       ORDER BY next_attempt_at, plan_id, run_key LIMIT 1 FOR UPDATE SKIP LOCKED)
     UPDATE automation_runs r SET generation=r.generation+1, lease_until=$2, lease_owner=$3,
       status=CASE WHEN r.status='due' THEN 'claimed' ELSE r.status END
     FROM next WHERE r.plan_id=next.plan_id AND r.run_key=next.run_key
     RETURNING r.*`,
    [now, now + LEASE_SECONDS, context.replicaId],
  );
  return (result.rows[0] as RunRow | undefined) ?? null;
}

/** A fenced write: it changes nothing once another claim superseded this one. */
async function update(
  pool: Pool,
  run: RunRow,
  assignments: string,
  values: readonly unknown[] = [],
): Promise<boolean> {
  const result = await pool.query(
    `UPDATE automation_runs SET ${assignments} WHERE plan_id=$1 AND run_key=$2 AND generation=$3`,
    [run.plan_id, run.run_key, run.generation, ...values],
  );
  return result.rowCount === 1;
}

const release = "lease_until=0, lease_owner=NULL";

function backoff(observations: number): number {
  return Math.min(60, 2 ** Math.min(observations + 1, 6));
}

/** Activates a plan whose setup is included and successful (or final); fenced on `authorized`. */
async function activatePlan(pool: Pool, run: RunRow): Promise<void> {
  await pool.query(
    "UPDATE automation_plans SET status='active', revision=revision+1, diagnostic=NULL WHERE id=$1 AND status='authorized'",
    [run.plan_id],
  );
}

/**
 * Plan effects of a terminal run, fenced on the plan's own state. A setup
 * that ends failed fails its plan even after inclusion activated it (a
 * reorganized or reverted install): no further occurrence is admitted.
 */
async function settlePlan(pool: Pool, run: RunRow, finalized: boolean): Promise<void> {
  if (run.kind === "setup") {
    if (finalized) await activatePlan(pool, run);
    else
      await pool.query(
        "UPDATE automation_plans SET status='failed', revision=revision+1, diagnostic='setup_failed' WHERE id=$1 AND status IN ('authorized','active','paused')",
        [run.plan_id],
      );
  }
  if (run.kind === "cancel")
    await pool.query(
      `UPDATE automation_plans SET status='cancelled', revision=revision+1,
         diagnostic=$2 WHERE id=$1 AND status='cancelling'`,
      [run.plan_id, finalized ? null : "cancel_calls_failed"],
    );
}

function admitted(plan: PlanRow, run: RunRow, now: number): "run" | "wait" | "skip" {
  if (run.kind === "setup") return plan.status === "authorized" ? "run" : "skip";
  if (run.kind === "cancel") return plan.status === "cancelling" ? "run" : "skip";
  if (run.closes_at !== null && now >= run.closes_at) return "skip";
  if (plan.status === "active") return "run";
  return plan.status === "paused" ? "wait" : "skip";
}

function sameCalls(
  left: readonly Readonly<{ target: string; value: string; data: string }>[],
  right: readonly ResolvedCall[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (call, index) =>
        call.target.toLowerCase() === right[index]?.target &&
        call.value === right[index]?.value &&
        call.data.toLowerCase() === right[index]?.data.toLowerCase(),
    )
  );
}

/** Observation only: it never sends, whatever it reads. */
async function observe(
  context: ServiceContext,
  plan: PlanRow,
  run: RunRow & { op_hash: `0x${string}` },
  gateway: OperationGateway,
): Promise<void> {
  const now = context.now();
  const seen = await gateway.observe(run.op_hash, runLane(run));
  if (seen === null || seen.status === "pending" || seen.status === "unreadable") {
    const changed = await update(
      context.pool,
      run,
      `status=$4, observations=observations+1, next_attempt_at=$5, reason=$6, transaction_hash=COALESCE($7::text, transaction_hash), ${release}`,
      [
        seen?.transactionHash ? "observed" : run.status,
        now + backoff(run.observations),
        seen === null ? "operation_unreadable" : `observation_${seen.status}`,
        seen?.transactionHash ?? null,
      ],
    );
    // An included, successful setup activates the plan before finality; its
    // occurrences run on their own lanes while the setup is still observed.
    if (changed && run.kind === "setup" && seen?.inclusion === "success")
      await activatePlan(context.pool, run);
    return;
  }
  if (seen.status === "abandoned") {
    // Proven never submitted: the identity may be replaced by a fresh send.
    const exhausted = run.attempts + 1 >= MAX_SEND_ATTEMPTS;
    await update(
      context.pool,
      run,
      `status=$4, op_hash=NULL, op_nonce=NULL, attempts=attempts+1, next_attempt_at=$5, reason='submission_abandoned', ${release}`,
      [exhausted ? "failed" : "prepared", now + 30],
    );
    if (exhausted) await settlePlan(context.pool, run, false);
    return;
  }
  if (seen.status !== "finalized" || seen.execution === null) {
    await update(context.pool, run, `status='failed', reason=$4, transaction_hash=$5, ${release}`, [
      `operation_${seen.status}`,
      seen.transactionHash,
    ]);
    await settlePlan(context.pool, run, false);
    return;
  }
  const bound =
    seen.execution.sender.toLowerCase() === plan.account &&
    run.calls !== null &&
    sameCalls(seen.execution.calls, run.calls);
  const succeeded = bound && seen.execution.outcome === "success";
  const changed = await update(
    context.pool,
    run,
    `status=$4, reason=$5, transaction_hash=$6, evidence=$7, ${release}`,
    [
      succeeded ? "finalized" : "failed",
      succeeded ? null : bound ? "reverted" : "evidence_mismatch",
      seen.transactionHash,
      { outcome: seen.execution.outcome },
    ],
  );
  if (changed) await settlePlan(context.pool, run, succeeded);
}

/** Drives one claimed run as far as it can go now, then releases its lease. */
export async function processRun(
  context: ServiceContext,
  run: RunRow,
  open: OpenGateway,
): Promise<void> {
  const plan = await readPlan(context.pool, run.plan_id);
  let current = run;
  if (current.status === "claimed") {
    const decision = admitted(plan, current, context.now());
    if (decision !== "run") {
      await update(
        context.pool,
        current,
        decision === "skip"
          ? `status='skipped', reason='admission_closed', ${release}`
          : `next_attempt_at=$4, reason='plan_paused', ${release}`,
        decision === "skip" ? [] : [context.now() + 10],
      );
      return;
    }
    const calls = resolveCalls(
      plan.definition,
      plan.terms,
      current.kind === "occurrence" ? { slot: current.slot as number } : current.kind,
    );
    if (
      !(await update(context.pool, current, "status='prepared', calls=$4", [JSON.stringify(calls)]))
    )
      return;
    current = { ...current, status: "prepared", calls };
  }

  let gateway: OperationGateway;
  try {
    gateway = await open(plan);
  } catch (error) {
    await defer(context, current, error);
    return;
  }
  try {
    if (current.status === "prepared" && current.op_hash === null) {
      if (current.kind === "occurrence" && admitted(plan, current, context.now()) !== "run") {
        await update(
          context.pool,
          current,
          `status='skipped', reason='admission_closed', ${release}`,
        );
        return;
      }
      try {
        await gateway.send(current.calls as readonly ResolvedCall[], runLane(current));
      } catch (error) {
        // Whatever failed, the journal decides: a linked hash means it may have been sent.
        const linked = await readRun(context.pool, current);
        if (linked?.op_hash) {
          await update(
            context.pool,
            current,
            `status='submitted', reason='submission_uncertain', next_attempt_at=$4, ${release}`,
            [context.now() + 5],
          );
          return;
        }
        await defer(context, current, error, true);
        return;
      }
      const linked = await readRun(context.pool, current);
      if (!linked?.op_hash) {
        await defer(context, current, new Error("operation_unlinked"));
        return;
      }
      if (!(await update(context.pool, current, "status='submitted', reason=NULL"))) return;
      current = { ...current, status: "submitted", op_hash: linked.op_hash };
    }
    if (current.op_hash !== null)
      await observe(context, plan, current as RunRow & { op_hash: `0x${string}` }, gateway);
  } catch (error) {
    await defer(context, current, error);
  } finally {
    await gateway.close().catch(() => undefined);
  }
}

async function readRun(pool: Pool, run: RunRow): Promise<RunRow | undefined> {
  return (
    await pool.query("SELECT * FROM automation_runs WHERE plan_id=$1 AND run_key=$2", [
      run.plan_id,
      run.run_key,
    ])
  ).rows[0] as RunRow | undefined;
}

function failureCode(error: unknown): string {
  const code =
    (error as { code?: unknown } | null)?.code ??
    (error instanceof Error ? error.message : undefined);
  return typeof code === "string" && /^[a-z0-9_]{1,80}$/u.test(code) ? code : "execution_deferred";
}

/** Releases the run for a later attempt; a counted send failure eventually fails it. */
async function defer(
  context: ServiceContext,
  run: RunRow,
  error: unknown,
  countsAsSend = false,
): Promise<void> {
  const budgetRetryAt = error instanceof BudgetError ? context.budgetRetryAt() : null;
  const exhausted =
    countsAsSend && !(error instanceof BudgetError) && run.attempts + 1 >= MAX_SEND_ATTEMPTS;
  await update(
    context.pool,
    run,
    `status=$4, attempts=attempts+$5, next_attempt_at=$6, reason=$7, ${release}`,
    [
      exhausted ? "failed" : run.status,
      countsAsSend && !(error instanceof BudgetError) ? 1 : 0,
      budgetRetryAt ?? context.now() + 30,
      failureCode(error),
    ],
  );
  if (exhausted) await settlePlan(context.pool, run, false);
}

/** One executor loop; run several per replica and any number of replicas. */
export async function executorLoop(
  context: ServiceContext,
  open: OpenGateway,
  signal: AbortSignal,
): Promise<void> {
  while (!signal.aborted) {
    const run = await claimRun(context).catch(() => null);
    if (run === null) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      continue;
    }
    await processRun(context, run, open).catch(() => undefined);
  }
}
