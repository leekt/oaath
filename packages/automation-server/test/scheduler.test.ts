import { createPlanTerms, hashPlanTerms } from "@oaath/automation";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ServiceContext } from "../src/context.js";
import { tick } from "../src/scheduler.js";
import { ACCOUNT, definition, testContext } from "./support/fixture.js";
import { postgresAvailable, startCluster, type TestCluster } from "./support/postgres.js";

const START = 1_900_000_000;
const PLAN = `0x${"ab".repeat(32)}` as `0x${string}`;

async function insertPlan(context: ServiceContext, status: string, setup = true) {
  const terms = createPlanTerms(definition, {
    planId: PLAN,
    account: ACCOUNT,
    now: START - 100,
    params: { budget: "1000" },
    occurrences: 3,
    startAt: START,
  });
  const stored = setup ? definition : { ...definition, setup: [] };
  await context.pool.query(
    `INSERT INTO automation_plans(id,app_id,user_id,account,key_scope,automation_id,definition,terms,plan_hash,
       creation_key,input_digest,status,next_at,created_at,grant_id)
     VALUES($1,'app','user',$2,'user',$3,$4,$5,$6,'k','d',$7,$8,$8,'grant-1')`,
    [PLAN, ACCOUNT, definition.id, stored, terms, hashPlanTerms(terms), status, START],
  );
}

const runs = async (context: ServiceContext) =>
  (
    await context.pool.query(
      "SELECT run_key, status, reason FROM automation_runs ORDER BY scheduled_at, run_key",
    )
  ).rows;
const status = async (context: ServiceContext) =>
  (await context.pool.query("SELECT status FROM automation_plans WHERE id=$1", [PLAN])).rows[0]
    .status;

describe.skipIf(!postgresAvailable)("scheduler", () => {
  let cluster: TestCluster;
  beforeAll(async () => {
    cluster = await startCluster();
  });
  afterAll(() => cluster?.stop());

  it("admits setup first, then one occurrence at a time", async () => {
    const clock = { now: START - 50 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "authorized");
    await tick(context);
    expect(await runs(context)).toEqual([{ run_key: "setup", status: "due", reason: null }]);
    await context.pool.query(
      "UPDATE automation_runs SET status='finalized' WHERE run_key='setup'; UPDATE automation_plans SET status='active'",
    );
    clock.now = START + 10;
    await tick(context);
    await tick(context);
    expect((await runs(context)).map((run) => run.run_key)).toEqual(["setup", "occurrence:0"]);
    // The next occurrence waits while one is open, and is skipped once its window closes.
    clock.now = START + 3600 + 700;
    await tick(context);
    expect((await runs(context)).slice(2)).toEqual([
      { run_key: "occurrence:1", status: "skipped", reason: "window_missed" },
    ]);
    await context.pool.end();
  });

  it("activates a plan without setup and completes it after its last occurrence", async () => {
    const clock = { now: START - 50 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "authorized", false);
    await tick(context);
    expect(await status(context)).toBe("active");
    clock.now = START + 2 * 3600 + 1000;
    await tick(context);
    expect((await runs(context)).map((run) => run.status)).toEqual([
      "skipped",
      "skipped",
      "skipped",
    ]);
    await tick(context);
    expect(await status(context)).toBe("completed");
    await context.pool.end();
  });

  it("admits nothing for a paused plan and skips what it missed", async () => {
    const clock = { now: START + 10 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "paused");
    await tick(context);
    expect(await runs(context)).toEqual([]);
    clock.now = START + 700;
    await tick(context);
    expect(await runs(context)).toEqual([
      { run_key: "occurrence:0", status: "skipped", reason: "window_missed" },
    ]);
    await context.pool.end();
  });

  it("cancels at once when nothing ever ran on chain", async () => {
    const clock = { now: START + 10 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "cancelling");
    await tick(context);
    expect(await status(context)).toBe("cancelled");
    expect(await runs(context)).toEqual([]);
    await context.pool.end();
  });

  it("runs the declared cancel calls once the plan touched the chain", async () => {
    const clock = { now: START + 10 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "cancelling");
    await context.pool.query(
      `INSERT INTO automation_runs(plan_id,run_key,kind,scheduled_at,status,op_hash)
       VALUES($1,'setup','setup',$2,'finalized',$3)`,
      [PLAN, START, `0x${"cd".repeat(32)}`],
    );
    await tick(context);
    expect((await runs(context)).map((run) => [run.run_key, run.status])).toEqual([
      ["setup", "finalized"],
      ["cancel", "due"],
    ]);
    expect(await status(context)).toBe("cancelling");
    await context.pool.end();
  });
});
