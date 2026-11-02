/**
 * Admission: turns plan state and the clock into runs. It never signs or
 * sends; the executor owns every run once admitted.
 *
 * ```text
 * plan     draft -> awaiting_consent -> authorized -> active <-> paused
 *          active|paused -> completed | expired;  any open plan -> cancelling -> cancelled
 *          authorized --setup included and successful--> active            (executor)
 *          authorized|active|paused --setup failed, reverted, dropped--> failed (executor)
 *          draft|awaiting_consent --terms end--> expired
 *          authorized --Grant end, setup never included--> expired (setup_not_included)
 * schedule the terms own every slot window: slot N opens at startAt + N*every and
 *          closes grace later, as the setup's on-chain plan and the Grant policy
 *          were signed. Activation moves no window; it gates admission, so slot N
 *          is due at max(its opening, activation) and is skipped once its window
 *          closes. The Grant end (the approved policy's validUntil + 1, never
 *          after the terms' endAt) caps every window; a slot opening at or after
 *          it is skipped as grant_expired.
 * deadline an authorized plan waits for its setup to be included and never
 *          expires before the Grant end, whatever its setup run's state; at the
 *          Grant end no operation can validate, so it expires. An active plan
 *          completes or expires only once none of its runs (setup included) is open.
 * run      inserted due (or skipped when its window already closed), with its lane
 * lane     derived here once and stored on the run: setup and cancel use the
 *          default lane 0. Occurrence slot N uses lane N + 1 when the plan has a
 *          setup, which alone installs the permission on lane 0 and may still
 *          await finality there; without a setup slot N uses lane N, so slot 0
 *          installs on lane 0.
 * occupied one unresolved operation per (plan, chain, lane), enforced by a unique
 *          index. Occurrences may be open together, up to `maxOpenSlots`, once one
 *          of the plan's operations is included (the permission install is on
 *          chain); before that, one at a time. A slot that cannot open waits and
 *          is skipped once its own window closes.
 * forbidden admitting an occurrence for a plan that is not active (so never
 *          before its setup is included and successful); a slot window past the
 *          Grant end; a cancel run while another run of the plan is open; two
 *          open runs on one chain and lane
 * ```
 *
 * On-demand plans (no schedule, setup or cancel calls):
 *
 * ```text
 * plan     draft -> awaiting_consent -> authorized -> active <-> paused   (active at once)
 *          active|paused --Grant end, no run open--> expired; never completed
 *          any open plan -> cancelling --no run open--> cancelled (no cancel calls)
 * request  admitted by `admitRequest` (POST /v1/plans/{id}/operations) in one
 *          transaction holding the plan row: the plan active and before its Grant
 *          end, the chain one of the plan's, every call inside the approved policy
 *          (`policyRefusal`). The exact calls are persisted on a new `request` run
 *          (due, closing at the Grant end) before the executor may send them.
 * replay   run key `request:<sha256(idempotencyKey)>`: the same key and body is the
 *          same run; another body is `idempotency_conflict`, never a new run
 * lane     per chain: until one of the plan's operations is included on that
 *          chain, one request at a time on lane 0 (its first operation installs
 *          the permission in enable mode); afterwards the lowest free lane in
 *          1..maxOpenSlots. No free lane refuses as `lanes_busy` (429); nothing waits.
 * forbidden admitting for a plan not active, past its Grant end, on a chain it does
 *          not name, or with a call outside the policy; a second run for one key
 * ```
 *
 * Every admission happens in one transaction holding the plan row, so
 * replicas may tick concurrently.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createHash } from "node:crypto";
import {
  canonicalJson,
  planEnd,
  type ScheduledAutomationDefinition,
  type ScheduledPlanTerms,
  slotTime,
} from "@oaath/automation";
import { evaluateGrantPolicyCoverage, type GrantPolicy } from "@oaath/protocol";
import { type PlanRow, type ServiceContext, ServiceError } from "./context.js";
import { type Client, transaction } from "./db.js";
import type { RunRow } from "./executor.js";
import { redeemPendingConsent } from "./oauth.js";
import { idempotencyKey } from "./plans.js";

const OPEN_RUN = "status IN ('due','claimed','prepared','submitted','observed')";
/** The terms' exclusive end (`planEnd`) in SQL, either kind. */
const TERMS_END = "COALESCE(terms->'schedule'->>'endAt', terms->>'endAt')::bigint";
const BATCH = 32;

async function openRuns(client: Client, planId: string): Promise<number> {
  const result = await client.query(
    `SELECT count(*)::integer AS n FROM automation_runs WHERE plan_id=$1 AND ${OPEN_RUN}`,
    [planId],
  );
  return result.rows[0].n as number;
}

async function hasOpenRun(client: Client, planId: string): Promise<boolean> {
  return (await openRuns(client, planId)) > 0;
}

/**
 * Whether an operation of the plan is already on chain `chainId`, so its
 * permission is installed or included there and explicit lanes may run beside
 * one another.
 */
async function installIncluded(client: Client, planId: string, chainId: number): Promise<boolean> {
  const result = await client.query(
    "SELECT 1 FROM automation_runs WHERE plan_id=$1 AND chain_id=$2 AND status IN ('observed','finalized') LIMIT 1",
    [planId, chainId],
  );
  return result.rowCount !== 0;
}

/** A scheduled plan's definition and terms; an on-demand plan never reaches these paths. */
function scheduled(plan: PlanRow): {
  definition: ScheduledAutomationDefinition;
  terms: ScheduledPlanTerms;
} {
  const { definition, terms } = plan;
  if (definition.kind !== "scheduled" || terms.kind !== "scheduled")
    throw new Error("plan_not_scheduled");
  return { definition, terms };
}

/**
 * The run's Kernel nonce lane: the default lane 0 for setup and cancel; an
 * occurrence's slot, moved past lane 0 when a setup holds that lane.
 */
function runLane(
  plan: PlanRow,
  kind: "setup" | "occurrence" | "cancel",
  slot: number | null,
): number {
  if (kind !== "occurrence") return 0;
  return (slot as number) + (scheduled(plan).definition.setup.length > 0 ? 1 : 0);
}

/** Unix seconds from which the plan's Grant no longer validates: its approved policy's end, never after the terms' end. */
function grantEnd(plan: PlanRow): number {
  const endAt = planEnd(plan.terms);
  const validUntil = plan.permission?.validUntil ?? null;
  return validUntil === null ? endAt : Math.min(endAt, validUntil + 1);
}

async function insertRun(
  client: Client,
  plan: PlanRow,
  run: Readonly<{
    key: string;
    kind: "setup" | "occurrence" | "cancel";
    slot: number | null;
    scheduledAt: number;
    closesAt: number | null;
    status: "due" | "skipped";
    reason: string | null;
  }>,
): Promise<void> {
  await client.query(
    `INSERT INTO automation_runs(plan_id,run_key,kind,slot,lane,scheduled_at,closes_at,status,reason,next_attempt_at,chain_id)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$6,$10) ON CONFLICT (plan_id, run_key) DO NOTHING`,
    [
      plan.id,
      run.key,
      run.kind,
      run.slot,
      runLane(plan, run.kind, run.slot),
      run.scheduledAt,
      run.closesAt,
      run.status,
      run.reason,
      scheduled(plan).terms.chainId,
    ],
  );
}

/** Occurrences whose time has come, for active and paused plans. */
async function admitOccurrences(client: Client, now: number, maxOpenSlots: number): Promise<void> {
  const plans = (
    await client.query(
      `SELECT * FROM automation_plans WHERE status IN ('active','paused') AND next_at<=$1
       ORDER BY next_at, id LIMIT ${BATCH} FOR UPDATE SKIP LOCKED`,
      [now],
    )
  ).rows as PlanRow[];
  for (const plan of plans) {
    const end = grantEnd(plan);
    let open = await openRuns(client, plan.id);
    if (plan.terms.kind === "on-demand") {
      // Requests are admitted by the API; here an on-demand plan only expires.
      const status = now >= end && open === 0 ? "expired" : plan.status;
      await client.query(
        `UPDATE automation_plans SET next_at=$2, status=$3,
           revision=revision+CASE WHEN status=$3 THEN 0 ELSE 1 END
         WHERE id=$1`,
        [plan.id, now < end ? end : now + 5, status],
      );
      continue;
    }
    const { terms } = scheduled(plan);
    const { schedule } = terms;
    const active = plan.status === "active";
    let slot = plan.next_slot;
    const limit = (await installIncluded(client, plan.id, terms.chainId)) ? maxOpenSlots : 1;
    while (slot < schedule.occurrences) {
      const at = slotTime(terms, slot);
      const closes = Math.min(at + schedule.grace, end);
      const outsideGrant = at >= end;
      if (!outsideGrant && now < at) break;
      const missed = outsideGrant || now >= closes;
      if (!missed && (!active || open >= limit)) break;
      await insertRun(client, plan, {
        key: `occurrence:${slot}`,
        kind: "occurrence",
        slot,
        scheduledAt: at,
        closesAt: closes,
        status: missed ? "skipped" : "due",
        reason: outsideGrant ? "grant_expired" : missed ? "window_missed" : null,
      });
      slot += 1;
      if (!missed) open += 1;
    }
    const done = slot >= schedule.occurrences;
    const nextAt = done
      ? now + 5
      : Math.max(slotTime(terms, slot) + (active ? 0 : schedule.grace), now + 5);
    const status =
      done && open === 0 && active
        ? "completed"
        : now >= end && open === 0
          ? "expired"
          : plan.status;
    await client.query(
      `UPDATE automation_plans SET next_slot=$2, next_at=$3, status=$4,
         revision=revision+CASE WHEN status=$4 THEN 0 ELSE 1 END
       WHERE id=$1`,
      [plan.id, slot, nextAt, status],
    );
  }
}

/** Authorized plans get their setup run; plans without setup become active at once. */
async function admitSetup(client: Client, now: number): Promise<void> {
  const plans = (
    await client.query(
      `SELECT * FROM automation_plans p WHERE status='authorized'
         AND NOT EXISTS (SELECT 1 FROM automation_runs r WHERE r.plan_id=p.id AND r.kind='setup')
       ORDER BY id LIMIT ${BATCH} FOR UPDATE SKIP LOCKED`,
    )
  ).rows as PlanRow[];
  for (const plan of plans) {
    // An on-demand plan has no setup: it is active once authorized.
    if (plan.definition.kind === "on-demand" || plan.definition.setup.length === 0) {
      await client.query(
        "UPDATE automation_plans SET status='active', revision=revision+1, next_at=$2 WHERE id=$1 AND status='authorized'",
        [plan.id, plan.terms.kind === "on-demand" ? now : plan.terms.schedule.startAt],
      );
      continue;
    }
    await insertRun(client, plan, {
      key: "setup",
      kind: "setup",
      slot: null,
      scheduledAt: now,
      closesAt: null,
      status: "due",
      reason: null,
    });
  }
}

/**
 * Cancelling plans: once nothing else of the plan is open, run the declared
 * cancel calls if the plan ever ran its setup or an occurrence; otherwise
 * there is nothing on chain to stop.
 */
async function admitCancellation(client: Client, now: number): Promise<void> {
  const plans = (
    await client.query(
      `SELECT * FROM automation_plans p WHERE status='cancelling'
         AND NOT EXISTS (SELECT 1 FROM automation_runs r WHERE r.plan_id=p.id AND r.kind='cancel')
       ORDER BY id LIMIT ${BATCH} FOR UPDATE SKIP LOCKED`,
    )
  ).rows as PlanRow[];
  for (const plan of plans) {
    if (await hasOpenRun(client, plan.id)) continue;
    const touched = await client.query(
      "SELECT 1 FROM automation_runs WHERE plan_id=$1 AND op_hash IS NOT NULL LIMIT 1",
      [plan.id],
    );
    if (
      plan.definition.kind === "on-demand" ||
      plan.definition.cancel.length === 0 ||
      touched.rowCount === 0 ||
      now >= planEnd(plan.terms)
    ) {
      await client.query(
        "UPDATE automation_plans SET status='cancelled', revision=revision+1 WHERE id=$1 AND status='cancelling'",
        [plan.id],
      );
      continue;
    }
    await insertRun(client, plan, {
      key: "cancel",
      kind: "cancel",
      slot: null,
      scheduledAt: now,
      closesAt: null,
      status: "due",
      reason: null,
    });
  }
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const DATA = /^0x(?:[0-9a-fA-F]{2})*$/u;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/u;
const MAX_REQUEST_CALLS = 16;

type RequestCall = Readonly<{ target: `0x${string}`; value: string; data: `0x${string}` }>;

/** The exact, lowercase calls of one request body, or a structured refusal. */
function requestBody(body: Record<string, unknown>): {
  chainId: number;
  calls: readonly RequestCall[];
  key: string;
} {
  const keys = Object.keys(body);
  if (
    keys.length !== 3 ||
    !["chainId", "calls", "idempotencyKey"].every((key) => keys.includes(key))
  )
    throw new ServiceError("request_invalid", 422);
  const key = idempotencyKey(body.idempotencyKey);
  const { chainId, calls } = body;
  if (typeof chainId !== "number" || !Number.isSafeInteger(chainId) || chainId < 1)
    throw new ServiceError("chain_id_invalid", 422);
  if (!Array.isArray(calls) || calls.length < 1 || calls.length > MAX_REQUEST_CALLS)
    throw new ServiceError("calls_invalid", 422);
  return {
    chainId,
    key,
    calls: calls.map((call: unknown) => {
      const entry = call as Record<string, unknown> | null;
      if (
        entry === null ||
        typeof entry !== "object" ||
        Array.isArray(entry) ||
        Object.keys(entry).length !== 3 ||
        typeof entry.to !== "string" ||
        !ADDRESS.test(entry.to) ||
        typeof entry.data !== "string" ||
        !DATA.test(entry.data) ||
        typeof entry.value !== "string" ||
        !DECIMAL.test(entry.value) ||
        BigInt(entry.value) >= 1n << 256n
      )
        throw new ServiceError("calls_invalid", 422);
      return Object.freeze({
        target: entry.to.toLowerCase() as `0x${string}`,
        value: entry.value,
        data: entry.data.toLowerCase() as `0x${string}`,
      });
    }),
  };
}

/**
 * Whether the calls fit the approved Grant policy at `now`, as the account's
 * CallPolicy will judge them: by target, selector and value. Empty calldata is
 * selector 0x00000000; one to three bytes have no selector and are refused.
 * The one owner of this check; null when the calls fit, else the refusal code.
 */
export function policyRefusal(
  policy: Readonly<GrantPolicy>,
  grantId: string,
  chainId: number,
  now: number,
  calls: readonly RequestCall[],
): string | null {
  if (calls.some((call) => call.data.length > 2 && call.data.length < 10))
    return "call_not_permitted";
  const result = evaluateGrantPolicyCoverage({
    policy,
    grantId,
    chainId,
    evaluatedAt: now,
    calls: calls.map((call) => ({ ...call, data: call.data === "0x" ? "0x00000000" : call.data })),
    // The per-chain count is the chain's to enforce; admission checks only the calls.
    usage: null,
  });
  return result.status === "denied" ? result.reason : null;
}

/**
 * The lane of a new request on one chain, or null when none is free. Before
 * one of the plan's operations is included on that chain, requests there run
 * one at a time on the default lane 0, whose first operation installs the
 * permission in enable mode; afterwards each takes the lowest free lane in
 * 1..maxOpenSlots.
 */
async function requestLane(
  client: Client,
  planId: string,
  chainId: number,
  maxOpenSlots: number,
): Promise<number | null> {
  const open = (
    await client.query(
      `SELECT lane FROM automation_runs WHERE plan_id=$1 AND chain_id=$2 AND ${OPEN_RUN}`,
      [planId, chainId],
    )
  ).rows.map((row) => row.lane as number);
  if (!(await installIncluded(client, planId, chainId))) return open.length === 0 ? 0 : null;
  for (let lane = 1; lane <= maxOpenSlots; lane += 1) if (!open.includes(lane)) return lane;
  return null;
}

/**
 * Admits one on-demand request: exact calls on one of the plan's chains,
 * persisted on a new `request` run before the executor may send them. The same
 * idempotency key with the same body is the same run; another body conflicts.
 */
export async function admitRequest(
  context: ServiceContext,
  planId: string,
  body: Record<string, unknown>,
): Promise<{ created: boolean; run: RunRow }> {
  const { chainId, calls, key } = requestBody(body);
  const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
  const runKey = `request:${sha256(key)}`;
  const digest = sha256(canonicalJson({ chainId, calls }));
  return transaction(context.pool, async (client) => {
    const plan = (
      await client.query("SELECT * FROM automation_plans WHERE id=$1 FOR UPDATE", [planId])
    ).rows[0] as PlanRow | undefined;
    if (plan === undefined) throw new ServiceError("plan_not_found", 404);
    const existing = (
      await client.query("SELECT * FROM automation_runs WHERE plan_id=$1 AND run_key=$2", [
        planId,
        runKey,
      ])
    ).rows[0] as (RunRow & { request_digest: string }) | undefined;
    if (existing !== undefined) {
      if (existing.request_digest !== digest) throw new ServiceError("idempotency_conflict", 409);
      return { created: false, run: existing };
    }
    if (plan.terms.kind !== "on-demand") throw new ServiceError("plan_not_on_demand", 409);
    if (plan.status !== "active" || plan.permission === null || plan.grant_id === null)
      throw new ServiceError("plan_not_active", 409);
    const now = context.now();
    const end = grantEnd(plan);
    if (now >= end) throw new ServiceError("plan_expired", 409);
    if (!plan.terms.chains.includes(chainId)) throw new ServiceError("chain_not_in_plan", 422);
    const refusal = policyRefusal(plan.permission, plan.grant_id, chainId, now, calls);
    if (refusal !== null) throw new ServiceError(refusal, 422);
    const lane = await requestLane(client, planId, chainId, context.config.maxOpenSlots);
    if (lane === null) throw new ServiceError("lanes_busy", 429);
    const inserted = await client.query(
      `INSERT INTO automation_runs(plan_id,run_key,kind,slot,chain_id,lane,scheduled_at,closes_at,status,
         calls,request_digest,next_attempt_at)
       VALUES($1,$2,'request',NULL,$3,$4,$5,$6,'due',$7,$8,$5) RETURNING *`,
      [planId, runKey, chainId, lane, now, end, JSON.stringify(calls), digest],
    );
    return { created: true, run: inserted.rows[0] as RunRow };
  });
}

/** One admission pass. Safe to run on every replica at once. */
export async function tick(context: ServiceContext): Promise<void> {
  const now = context.now();
  await transaction(context.pool, async (client) => {
    // Unapproved plans expire at the terms' end. An authorized plan waits for
    // its setup until the Grant end, then expires: nothing can validate after it.
    await client.query(
      `UPDATE automation_plans SET status='expired', revision=revision+1,
         diagnostic=CASE WHEN status='authorized' THEN 'setup_not_included' ELSE diagnostic END
       WHERE status IN ('draft','awaiting_consent','authorized')
         AND LEAST(${TERMS_END}, COALESCE((permission->>'validUntil')::bigint + 1, ${TERMS_END}))<=$1`,
      [now],
    );
    await admitSetup(client, now);
    await admitOccurrences(client, now, context.config.maxOpenSlots);
    await admitCancellation(client, now);
  });
  const consent = await context.pool.query(
    `UPDATE automation_plans SET next_consent_at=$2 WHERE id IN (
       SELECT id FROM automation_plans WHERE status='awaiting_consent' AND next_consent_at<=$1
       ORDER BY next_consent_at LIMIT 8 FOR UPDATE SKIP LOCKED) RETURNING id`,
    [now, now + 30],
  );
  for (const row of consent.rows) {
    await redeemPendingConsent(context, row.id).catch(() => undefined);
  }
}
