import { createPlanTerms, hashPlanTerms } from "@oaath/automation";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ServiceContext } from "../src/context.js";
import { tick } from "../src/scheduler.js";
import { ACCOUNT, definition, testContext } from "./support/fixture.js";
import { postgresAvailable, startCluster, type TestCluster } from "./support/postgres.js";

const START = 1_900_000_000;
const PLAN = `0x${"ab".repeat(32)}` as `0x${string}`;

async function insertPlan(context: ServiceContext, status: string, setup = true, occurrences = 3) {
  const terms = createPlanTerms(definition, {
    planId: PLAN,
    account: ACCOUNT,
    now: START - 100,
    params: { budget: "1000" },
    occurrences,
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
const lanes = async (context: ServiceContext) =>
  (
    await context.pool.query(
      "SELECT run_key, lane, status FROM automation_runs ORDER BY scheduled_at, run_key",
    )
  ).rows;
/** Marks a run included but not final, as observation leaves it. */
const include = (context: ServiceContext, key: string) =>
  context.pool.query(
    "UPDATE automation_runs SET status='observed', op_hash=$2, transaction_hash=$2 WHERE run_key=$1",
    [key, `0x${"ef".repeat(32)}`],
  );
const status = async (context: ServiceContext) =>
  (await context.pool.query("SELECT status FROM automation_plans WHERE id=$1", [PLAN])).rows[0]
    .status;

describe.skipIf(!postgresAvailable)("scheduler", () => {
  let cluster: TestCluster;
  beforeAll(async () => {
    cluster = await startCluster();
  });
  afterAll(() => cluster?.stop());

  it("admits no occurrence until setup finalized, even while setup is included", async () => {
    const clock = { now: START - 50 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "authorized");
    await tick(context);
    expect(await lanes(context)).toEqual([{ run_key: "setup", lane: 0, status: "due" }]);
    await include(context, "setup");
    clock.now = START + 10;
    await tick(context);
    expect((await runs(context)).map((run) => run.run_key)).toEqual(["setup"]);
    await context.pool.query(
      "UPDATE automation_runs SET status='finalized' WHERE run_key='setup'; UPDATE automation_plans SET status='active'",
    );
    await tick(context);
    expect(await lanes(context)).toEqual([
      { run_key: "setup", lane: 0, status: "finalized" },
      { run_key: "occurrence:0", lane: 0, status: "due" },
    ]);
    await context.pool.end();
  });

  it("opens the next slot on its own lane, on time, while the previous one awaits finality", async () => {
    const clock = { now: START + 10 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "active");
    await context.pool.query(
      `INSERT INTO automation_runs(plan_id,run_key,kind,lane,scheduled_at,status)
       VALUES($1,'setup','setup',0,$2,'finalized')`,
      [PLAN, START - 50],
    );
    await tick(context);
    await include(context, "occurrence:0");
    clock.now = START + 3600 + 1;
    await tick(context);
    expect((await lanes(context)).slice(1)).toEqual([
      { run_key: "occurrence:0", lane: 0, status: "observed" },
      { run_key: "occurrence:1", lane: 1, status: "due" },
    ]);
    await context.pool.end();
  });

  it("holds open slots at the cap, then skips a slot whose window closes", async () => {
    const clock = { now: START + 10 };
    const context = await testContext(await cluster.database(), clock, "replica-a", {
      maxOpenSlots: 2,
    });
    await insertPlan(context, "active", true, 4);
    await context.pool.query(
      `INSERT INTO automation_runs(plan_id,run_key,kind,lane,scheduled_at,status)
       VALUES($1,'setup','setup',0,$2,'finalized')`,
      [PLAN, START - 50],
    );
    await tick(context);
    clock.now = START + 3600 + 1;
    await tick(context);
    // Two slots open; the third waits while its window is open, then is skipped.
    clock.now = START + 7200 + 1;
    await tick(context);
    expect((await runs(context)).map((run) => run.run_key)).toEqual([
      "setup",
      "occurrence:0",
      "occurrence:1",
    ]);
    clock.now = START + 7200 + 600;
    await tick(context);
    expect((await runs(context)).slice(3)).toEqual([
      { run_key: "occurrence:2", status: "skipped", reason: "window_missed" },
    ]);
    // A freed lane lets the next slot in on time.
    await context.pool.query(
      "UPDATE automation_runs SET status='finalized' WHERE run_key='occurrence:0'",
    );
    clock.now = START + 3 * 3600 + 1;
    await tick(context);
    expect((await lanes(context)).slice(4)).toEqual([
      { run_key: "occurrence:3", lane: 3, status: "due" },
    ]);
    await context.pool.end();
  });

  it("serializes slots until the first operation of a plan without setup is included", async () => {
    const clock = { now: START + 10 };
    const context = await testContext(await cluster.database(), clock);
    await insertPlan(context, "active", false);
    await tick(context);
    clock.now = START + 3600 + 1;
    await tick(context);
    // Slot 0 enables the permission on the default lane; no lane may race it.
    expect((await runs(context)).map((run) => run.run_key)).toEqual(["occurrence:0"]);
    await include(context, "occurrence:0");
    clock.now += 5;
    await tick(context);
    expect(await lanes(context)).toEqual([
      { run_key: "occurrence:0", lane: 0, status: "observed" },
      { run_key: "occurrence:1", lane: 1, status: "due" },
    ]);
    await context.pool.end();
  });

  it("admits each slot once across replicas ticking together", async () => {
    const clock = { now: START + 10 };
    const url = await cluster.database();
    const a = await testContext(url, clock, "replica-a");
    const b = await testContext(url, clock, "replica-b");
    await insertPlan(a, "active");
    await a.pool.query(
      `INSERT INTO automation_runs(plan_id,run_key,kind,lane,scheduled_at,status)
       VALUES($1,'setup','setup',0,$2,'finalized')`,
      [PLAN, START - 50],
    );
    await Promise.all([tick(a), tick(b), tick(a), tick(b)]);
    clock.now = START + 3600 + 1;
    await Promise.all([tick(a), tick(b), tick(a), tick(b)]);
    expect((await lanes(a)).slice(1)).toEqual([
      { run_key: "occurrence:0", lane: 0, status: "due" },
      { run_key: "occurrence:1", lane: 1, status: "due" },
    ]);
    await a.pool.end();
    await b.pool.end();
  });

  it("refuses a second open run on one lane", async () => {
    const context = await testContext(await cluster.database(), { now: START });
    await insertPlan(context, "active");
    const insert = (key: string, status: string) =>
      context.pool.query(
        `INSERT INTO automation_runs(plan_id,run_key,kind,slot,lane,scheduled_at,status)
         VALUES($1,$2,'occurrence',0,0,$3,$4)`,
        [PLAN, key, START, status],
      );
    await insert("setup-like", "observed");
    await expect(insert("occurrence:0", "due")).rejects.toMatchObject({ code: "23505" });
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
      `INSERT INTO automation_runs(plan_id,run_key,kind,lane,scheduled_at,status,op_hash)
       VALUES($1,'setup','setup',0,$2,'finalized',$3)`,
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
