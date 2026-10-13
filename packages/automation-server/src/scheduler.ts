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
 * occupied one unresolved operation per (plan, lane), enforced by a unique index.
 *          Occurrences may be open together, up to `maxOpenSlots`, once one of
 *          the plan's operations is included (the permission install is on
 *          chain); before that, one at a time. A slot that cannot open waits and
 *          is skipped once its own window closes.
 * forbidden admitting an occurrence for a plan that is not active (so never
 *          before its setup is included and successful); a slot window past the
 *          Grant end; a cancel run while another run of the plan is open; two
 *          open runs on one lane
 * ```
 *
 * Every admission happens in one transaction holding the plan row, so
 * replicas may tick concurrently.
 *
 * @author taek <leekt216@gmail.com>
 */
import { slotTime } from "@oaath/automation";
import type { PlanRow, ServiceContext } from "./context.js";
import { type Client, transaction } from "./db.js";
import { redeemPendingConsent } from "./oauth.js";

const OPEN_RUN = "status IN ('due','claimed','prepared','submitted','observed')";
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
 * Whether an operation of the plan is already on chain, so its permission is
 * installed or included and explicit lanes may run beside one another.
 */
async function installIncluded(client: Client, planId: string): Promise<boolean> {
  const result = await client.query(
    "SELECT 1 FROM automation_runs WHERE plan_id=$1 AND status IN ('observed','finalized') LIMIT 1",
    [planId],
  );
  return result.rowCount !== 0;
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
  return (slot as number) + (plan.definition.setup.length > 0 ? 1 : 0);
}

/** Unix seconds from which the plan's Grant no longer validates: its approved policy's end, never after the terms' end. */
function grantEnd(plan: PlanRow): number {
  const { endAt } = plan.terms.schedule;
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
    `INSERT INTO automation_runs(plan_id,run_key,kind,slot,lane,scheduled_at,closes_at,status,reason,next_attempt_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$6) ON CONFLICT (plan_id, run_key) DO NOTHING`,
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
    const { schedule } = plan.terms;
    const active = plan.status === "active";
    const end = grantEnd(plan);
    let slot = plan.next_slot;
    let open = await openRuns(client, plan.id);
    const limit = (await installIncluded(client, plan.id)) ? maxOpenSlots : 1;
    while (slot < schedule.occurrences) {
      const at = slotTime(plan.terms, slot);
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
      : Math.max(slotTime(plan.terms, slot) + (active ? 0 : schedule.grace), now + 5);
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
    if (plan.definition.setup.length === 0) {
      await client.query(
        "UPDATE automation_plans SET status='active', revision=revision+1, next_at=$2 WHERE id=$1 AND status='authorized'",
        [plan.id, plan.terms.schedule.startAt],
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
      plan.definition.cancel.length === 0 ||
      touched.rowCount === 0 ||
      now >= plan.terms.schedule.endAt
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
         AND LEAST((terms->'schedule'->>'endAt')::bigint,
           COALESCE((permission->>'validUntil')::bigint + 1, (terms->'schedule'->>'endAt')::bigint))<=$1`,
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
