/**
 * Admission: turns plan state and the clock into runs. It never signs or
 * sends; the executor owns every run once admitted.
 *
 * ```text
 * plan     draft -> awaiting_consent -> authorized -> active <-> paused
 *          active|paused -> completed | expired;  any open plan -> cancelling -> cancelled
 *          authorized --setup failed--> failed
 * run      inserted due (or skipped when its window already closed)
 * occupied one open run per plan: a new occurrence waits while one is open,
 *          and is skipped once its own window closes
 * forbidden admitting an occurrence for a plan that is not active; a cancel run
 *          while another run of the plan is open
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

async function hasOpenRun(client: Client, planId: string): Promise<boolean> {
  const result = await client.query(
    `SELECT 1 FROM automation_runs WHERE plan_id=$1 AND ${OPEN_RUN} LIMIT 1`,
    [planId],
  );
  return result.rowCount !== 0;
}

async function insertRun(
  client: Client,
  run: Readonly<{
    planId: string;
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
    `INSERT INTO automation_runs(plan_id,run_key,kind,slot,scheduled_at,closes_at,status,reason,next_attempt_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$5) ON CONFLICT DO NOTHING`,
    [
      run.planId,
      run.key,
      run.kind,
      run.slot,
      run.scheduledAt,
      run.closesAt,
      run.status,
      run.reason,
    ],
  );
}

/** Occurrences whose time has come, for active and paused plans. */
async function admitOccurrences(client: Client, now: number): Promise<void> {
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
    let slot = plan.next_slot;
    while (slot < schedule.occurrences) {
      const at = slotTime(plan.terms, slot);
      const closes = at + schedule.grace;
      if (now < at) break;
      const missed = now >= closes;
      if (!missed && (!active || (await hasOpenRun(client, plan.id)))) break;
      await insertRun(client, {
        planId: plan.id,
        key: `occurrence:${slot}`,
        kind: "occurrence",
        slot,
        scheduledAt: at,
        closesAt: closes,
        status: missed ? "skipped" : "due",
        reason: missed ? "window_missed" : null,
      });
      slot += 1;
      if (!missed) break;
    }
    const done = slot >= schedule.occurrences;
    const open = await hasOpenRun(client, plan.id);
    const nextAt = done
      ? now + 5
      : Math.max(slotTime(plan.terms, slot) + (active ? 0 : schedule.grace), now + 5);
    const status =
      done && !open && active
        ? "completed"
        : now >= schedule.endAt && !open
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
    await insertRun(client, {
      planId: plan.id,
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
    await insertRun(client, {
      planId: plan.id,
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
    await client.query(
      `UPDATE automation_plans SET status='expired', revision=revision+1
       WHERE status IN ('draft','awaiting_consent','authorized') AND (terms->'schedule'->>'endAt')::bigint<=$1`,
      [now],
    );
    await admitSetup(client, now);
    await admitOccurrences(client, now);
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
