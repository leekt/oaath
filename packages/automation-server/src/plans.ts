/**
 * Plan lifecycle commands and their retained projections. Reads never touch
 * the chain: status and history come from PostgreSQL.
 *
 * @author taek <leekt216@gmail.com>
 */
import { createHash, randomBytes } from "node:crypto";
import { AutomationError, canonicalJson, createPlanTerms, hashPlanTerms } from "@oaath/automation";
import { type PlanRow, readPlan, type ServiceContext, ServiceError } from "./context.js";
import type { Principal } from "./sessions.js";
import { keyScope } from "./sessions.js";

const RUN_STATUSES = [
  "due",
  "claimed",
  "prepared",
  "submitted",
  "observed",
  "finalized",
  "failed",
  "skipped",
] as const;

function userOf(principal: Principal) {
  if (principal.user === null) throw new ServiceError("user_session_required", 403);
  return principal.user;
}

/** The caller's own plan: its application, and its user unless an application credential. */
export async function ownPlan(
  context: ServiceContext,
  principal: Principal,
  id: string,
): Promise<PlanRow> {
  if (!/^0x[0-9a-f]{64}$/u.test(id)) throw new ServiceError("plan_not_found", 404);
  const plan = await readPlan(context.pool, id).catch(() => null);
  if (
    plan === null ||
    plan.app_id !== principal.appId ||
    (principal.user !== null &&
      (plan.user_id !== principal.user.userId || plan.account !== principal.user.account))
  )
    throw new ServiceError("plan_not_found", 404);
  return plan;
}

export async function projectPlan(context: ServiceContext, plan: PlanRow) {
  const counts = await context.pool.query(
    "SELECT status, count(*)::integer AS n FROM automation_runs WHERE plan_id=$1 GROUP BY status",
    [plan.id],
  );
  const progress = Object.fromEntries(RUN_STATUSES.map((status) => [status, 0]));
  for (const row of counts.rows) progress[row.status] = row.n;
  return {
    id: plan.id,
    automation: {
      id: plan.definition.id,
      name: plan.definition.name,
      hash: plan.terms.automation.hash,
    },
    keyScope: plan.key_scope,
    status: plan.status,
    revision: plan.revision,
    terms: plan.terms,
    permission: plan.permission,
    signer: plan.signer,
    grantId: plan.grant_id,
    progress,
    nextSlot: plan.next_slot,
    nextAt: plan.next_at,
    diagnostic: plan.diagnostic,
    asOf: context.now(),
  };
}

export async function createPlan(
  context: ServiceContext,
  principal: Principal,
  body: Record<string, unknown>,
): Promise<{ created: boolean; plan: PlanRow }> {
  const user = userOf(principal);
  const allowed = ["automation", "params", "occurrences", "startAt", "idempotencyKey"];
  if (Object.keys(body).some((key) => !allowed.includes(key)))
    throw new ServiceError("plan_invalid", 422);
  const { automation, idempotencyKey } = body;
  if (
    typeof idempotencyKey !== "string" ||
    idempotencyKey.length < 1 ||
    idempotencyKey.length > 128 ||
    idempotencyKey.trim() !== idempotencyKey
  )
    throw new ServiceError("idempotency_key_invalid", 422);
  const definition =
    typeof automation === "string" ? context.definitions.get(automation) : undefined;
  if (definition === undefined) throw new ServiceError("automation_not_found", 404);
  const scope = await keyScope(context, principal.appId);
  const input = {
    params: body.params as Record<string, string | boolean> | undefined,
    occurrences: body.occurrences as number | undefined,
    startAt: body.startAt as number | undefined,
  };
  const id = `0x${randomBytes(32).toString("hex")}` as `0x${string}`;
  let terms: ReturnType<typeof createPlanTerms>;
  try {
    terms = createPlanTerms(definition, {
      planId: id,
      account: user.account,
      now: context.now(),
      ...(input.params === undefined ? {} : { params: input.params }),
      ...(input.occurrences === undefined ? {} : { occurrences: input.occurrences }),
      ...(input.startAt === undefined ? {} : { startAt: input.startAt }),
    });
  } catch (error) {
    if (error instanceof AutomationError) throw new ServiceError(error.code, 422);
    throw error;
  }
  // The same key with the same input is the same plan; anything else conflicts.
  const digest = createHash("sha256")
    .update(
      canonicalJson({
        automation: terms.automation,
        userId: user.userId,
        account: user.account,
        keyScope: scope,
        input: { ...input, startAt: input.startAt ?? null },
      }),
    )
    .digest("hex");
  const inserted = await context.pool.query(
    `INSERT INTO automation_plans(id,app_id,user_id,account,key_scope,automation_id,definition,terms,plan_hash,
       creation_key,input_digest,status,next_at,created_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'draft',$12,$13)
     ON CONFLICT (app_id,account,creation_key) DO NOTHING RETURNING id`,
    [
      id,
      principal.appId,
      user.userId,
      user.account,
      scope,
      definition.id,
      definition,
      terms,
      hashPlanTerms(terms),
      idempotencyKey,
      digest,
      terms.schedule.startAt,
      context.now(),
    ],
  );
  if (inserted.rowCount === 1) return { created: true, plan: await readPlan(context.pool, id) };
  const existing = (
    await context.pool.query(
      "SELECT id, input_digest FROM automation_plans WHERE app_id=$1 AND account=$2 AND creation_key=$3",
      [principal.appId, user.account, idempotencyKey],
    )
  ).rows[0];
  if (existing === undefined || existing.input_digest !== digest)
    throw new ServiceError("idempotency_conflict", 409);
  return { created: false, plan: await readPlan(context.pool, existing.id) };
}

export async function listPlans(context: ServiceContext, principal: Principal) {
  const rows = (
    await context.pool.query(
      `SELECT * FROM automation_plans WHERE app_id=$1 AND ($2::text IS NULL OR (user_id=$2 AND account=$3))
       ORDER BY created_at DESC, id LIMIT 100`,
      [principal.appId, principal.user?.userId ?? null, principal.user?.account ?? null],
    )
  ).rows as PlanRow[];
  return { plans: await Promise.all(rows.map((row) => projectPlan(context, row))) };
}

export async function listRuns(context: ServiceContext, plan: PlanRow, query: URLSearchParams) {
  const after = Number(query.get("after") ?? -1);
  const limit = Number(query.get("limit") ?? 50);
  if (!Number.isSafeInteger(after) || !Number.isSafeInteger(limit))
    throw new ServiceError("page_invalid", 422);
  const rows = (
    await context.pool.query(
      `SELECT * FROM automation_runs WHERE plan_id=$1 AND (slot IS NULL OR slot>$2)
       ORDER BY COALESCE(slot,-1), run_key LIMIT $3`,
      [plan.id, after, Math.min(Math.max(limit, 1), 100)],
    )
  ).rows;
  return {
    runs: rows.map((run) => ({
      kind: run.kind,
      slot: run.slot,
      status: run.status,
      scheduledAt: run.scheduled_at,
      closesAt: run.closes_at,
      operation: run.op_hash,
      transactionHash: run.transaction_hash,
      reason: run.reason,
    })),
  };
}

/** Pause stops new occurrences; work already journaled is still observed. */
export async function pausePlan(context: ServiceContext, plan: PlanRow): Promise<void> {
  if (plan.status === "paused") return;
  const result = await context.pool.query(
    "UPDATE automation_plans SET status='paused', revision=revision+1 WHERE id=$1 AND status='active'",
    [plan.id],
  );
  if (result.rowCount !== 1) throw new ServiceError("plan_not_active");
}

export async function resumePlan(context: ServiceContext, plan: PlanRow): Promise<void> {
  if (plan.status === "active") return;
  const result = await context.pool.query(
    `UPDATE automation_plans SET status='active', revision=revision+1, next_at=LEAST(next_at,$2)
     WHERE id=$1 AND status='paused' AND (terms->'schedule'->>'endAt')::bigint>$2`,
    [plan.id, context.now()],
  );
  if (result.rowCount !== 1) throw new ServiceError("plan_not_paused");
}

/**
 * Stops admission at once. A plan with authority on chain moves to
 * `cancelling`, where the scheduler runs its declared cancel calls.
 */
export async function cancelPlan(context: ServiceContext, plan: PlanRow): Promise<void> {
  if (plan.status === "cancelling" || plan.status === "cancelled") return;
  const result = await context.pool.query(
    `UPDATE automation_plans SET revision=revision+1, oauth=NULL, oauth_state=NULL, next_consent_at=NULL,
       status=CASE WHEN status IN ('draft','awaiting_consent') THEN 'cancelled' ELSE 'cancelling' END
     WHERE id=$1 AND status IN ('draft','awaiting_consent','authorized','active','paused')`,
    [plan.id],
  );
  if (result.rowCount !== 1) throw new ServiceError("plan_not_cancellable");
}
