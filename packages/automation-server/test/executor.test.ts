/**
 * The run state machine against real PostgreSQL with a scripted gateway. The
 * gateway journals through the real Operation store adapter, exactly where
 * the SDK journals a prepared identity before signing or sending it.
 */
import { createPlanTerms, hashPlanTerms, resolveCalls } from "@oaath/automation";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ServiceContext } from "../src/context.js";
import {
  claimRun,
  LEASE_SECONDS,
  type Observation,
  type OperationGateway,
  processRun,
} from "../src/executor.js";
import { createOperationStore } from "../src/store.js";
import { ACCOUNT, definition, testContext } from "./support/fixture.js";
import { postgresAvailable, startCluster, type TestCluster } from "./support/postgres.js";

const START = 1_900_000_000;

async function insertPlan(
  context: ServiceContext,
  status: string,
  planId = `0x${"ab".repeat(32)}`,
): Promise<{ planId: `0x${string}`; grantId: string }> {
  const terms = createPlanTerms(definition, {
    planId: planId as `0x${string}`,
    account: ACCOUNT,
    now: START - 100,
    params: { budget: "1000" },
    occurrences: 3,
    startAt: START,
  });
  const grantId = `grant-${planId.slice(2, 10)}`;
  await context.pool.query(
    `INSERT INTO automation_plans(id,app_id,user_id,account,key_scope,automation_id,definition,terms,plan_hash,
       creation_key,input_digest,status,next_at,created_at,grant_id)
     VALUES($1,'app','user',$2,'user',$3,$4,$5,$6,$1,'d',$7,$8,$8,$9)`,
    [
      planId,
      ACCOUNT,
      definition.id,
      definition,
      terms,
      hashPlanTerms(terms),
      status,
      START,
      grantId,
    ],
  );
  return { planId: planId as `0x${string}`, grantId };
}

async function insertRun(
  context: ServiceContext,
  planId: string,
  key: string,
  kind: "setup" | "occurrence" | "cancel",
  slot: number | null,
) {
  await context.pool.query(
    `INSERT INTO automation_runs(plan_id,run_key,kind,slot,scheduled_at,closes_at,status,next_attempt_at)
     VALUES($1,$2,$3,$4,$5,$6,'due',$5)`,
    [planId, key, kind, slot, START, slot === null ? null : START + 600],
  );
}

/** Journals like the SDK, then answers observations from a script. */
function scriptedGateway(
  context: ServiceContext,
  grantId: string,
  script: { observations: Observation[]; failSend?: "before_journal" | "after_journal" },
) {
  const counts = { sends: 0, observations: 0 };
  const journal = createOperationStore(context.pool);
  const hash = `0x${"cd".repeat(32)}` as const;
  const gateway: OperationGateway = {
    async send() {
      counts.sends += 1;
      if (script.failSend === "before_journal") throw new Error("bundler_unavailable");
      const committed = await journal.compareAndSwap({
        key: { grantId, chainId: 31337, kind: "execution" },
        expectedStoreRevision: null,
        next: {
          version: "oaath.operation-store-record/v1",
          storeRevision: 1,
          updatedAt: START,
          value: { state: "prepared", identity: { userOperationHash: hash, nonce: "7" } },
        },
        expectedArchiveAbsentUserOperationHash: hash,
        archive: null,
      });
      if (!committed) throw new Error("journal_refused");
      if (script.failSend === "after_journal") throw new Error("submission_timeout");
      return hash;
    },
    async observe(id) {
      expect(id).toBe(hash);
      counts.observations += 1;
      return (
        script.observations.shift() ?? { status: "pending", transactionHash: null, execution: null }
      );
    },
    async close() {},
  };
  return { counts, open: async () => gateway, hash };
}

async function run(context: ServiceContext, planId: string, key: string) {
  return (
    await context.pool.query("SELECT * FROM automation_runs WHERE plan_id=$1 AND run_key=$2", [
      planId,
      key,
    ])
  ).rows[0];
}

/** Claims and processes until nothing is due at the current time. */
async function drain(context: ServiceContext, open: () => Promise<OperationGateway>) {
  for (let index = 0; index < 4; index += 1) {
    const claimed = await claimRun(context);
    if (claimed === null) return;
    await processRun(context, claimed, open);
  }
}

describe.skipIf(!postgresAvailable)("executor", () => {
  let cluster: TestCluster;
  beforeAll(async () => {
    cluster = await startCluster();
  });
  afterAll(() => cluster?.stop());

  it("drives one occurrence to finality with one send and retries only observation", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    const terms = (
      await context.pool.query("SELECT terms FROM automation_plans WHERE id=$1", [planId])
    ).rows[0].terms;
    const calls = resolveCalls(definition, terms, { slot: 0 });
    const pending: Observation = { status: "pending", transactionHash: null, execution: null };
    const gateway = scriptedGateway(context, grantId, {
      observations: [
        pending,
        { status: "unreadable", transactionHash: null, execution: null },
        { status: "pending", transactionHash: `0x${"ee".repeat(32)}`, execution: null },
        {
          status: "finalized",
          transactionHash: `0x${"ee".repeat(32)}`,
          execution: { sender: ACCOUNT, calls, outcome: "success" },
        },
      ],
    });

    await drain(context, gateway.open);
    let row = await run(context, planId, "occurrence:0");
    expect(row.status).toBe("submitted");
    expect(row.op_hash).toBe(gateway.hash);
    expect(row.op_nonce).toBe("7");
    expect(gateway.counts.sends).toBe(1);

    for (const expected of ["submitted", "observed", "finalized"]) {
      clock.now += 120;
      await drain(context, gateway.open);
      row = await run(context, planId, "occurrence:0");
      expect(row.status).toBe(expected);
    }
    expect(gateway.counts).toEqual({ sends: 1, observations: 4 });
    expect(row.transaction_hash).toBe(`0x${"ee".repeat(32)}`);
    await context.pool.end();
  });

  it("never sends again once the journal holds the identity", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    // The send is journaled, then its reply is lost.
    const gateway = scriptedGateway(context, grantId, {
      observations: [],
      failSend: "after_journal",
    });
    await drain(context, gateway.open);
    expect((await run(context, planId, "occurrence:0")).status).toBe("submitted");
    for (let pass = 0; pass < 5; pass += 1) {
      clock.now += 120;
      await drain(context, gateway.open);
    }
    expect(gateway.counts.sends).toBe(1);
    expect(gateway.counts.observations).toBe(5);
    expect((await run(context, planId, "occurrence:0")).status).toBe("submitted");
    await context.pool.end();
  });

  it("resends only while nothing was journaled, and fails after bounded attempts", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    const gateway = scriptedGateway(context, grantId, {
      observations: [],
      failSend: "before_journal",
    });
    await drain(context, gateway.open);
    let row = await run(context, planId, "occurrence:0");
    expect([row.status, row.op_hash, row.attempts]).toEqual(["prepared", null, 1]);
    clock.now += 31;
    await drain(context, gateway.open);
    clock.now += 31;
    await drain(context, gateway.open);
    row = await run(context, planId, "occurrence:0");
    expect([row.status, row.attempts]).toEqual(["failed", 3]);
    expect(gateway.counts.sends).toBe(3);
    await context.pool.end();
  });

  it("recovers a crash after journaling by observing, never sending", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    const first = scriptedGateway(context, grantId, { observations: [] });
    // Claim and prepare as processRun does, journal like the SDK, then die
    // before recording the submission.
    expect(await claimRun(context)).not.toBeNull();
    await context.pool.query(
      "UPDATE automation_runs SET status='prepared', calls='[]' WHERE plan_id=$1",
      [planId],
    );
    await (await first.open()).send([]);
    expect((await run(context, planId, "occurrence:0")).op_hash).toBe(first.hash);
    // The lease expires; another replica resumes from PostgreSQL alone.
    clock.now += LEASE_SECONDS + 1;
    const replica = { ...context, replicaId: "replica-b" };
    const second = scriptedGateway(context, grantId, { observations: [] });
    await drain(replica, second.open);
    expect(second.counts.sends).toBe(0);
    expect(second.counts.observations).toBe(1);
    await context.pool.end();
  });

  it("refuses to journal an identity no prepared run claims", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { grantId } = await insertPlan(context, "active");
    const gateway = scriptedGateway(context, grantId, { observations: [] });
    await expect((await gateway.open()).send([])).rejects.toThrow("journal_refused");
    const rows = await context.pool.query("SELECT count(*)::int AS n FROM automation_operations");
    expect(rows.rows[0].n).toBe(0);
    await context.pool.end();
  });

  it("skips an occurrence whose window closed before it was sent", async () => {
    const clock = { now: START + 601 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    const gateway = scriptedGateway(context, grantId, { observations: [] });
    await drain(context, gateway.open);
    expect((await run(context, planId, "occurrence:0")).status).toBe("skipped");
    expect(gateway.counts.sends).toBe(0);
    await context.pool.end();
  });

  it("activates the plan when its setup finalizes", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "authorized");
    await insertRun(context, planId, "setup", "setup", null);
    const terms = (
      await context.pool.query("SELECT terms FROM automation_plans WHERE id=$1", [planId])
    ).rows[0].terms;
    const gateway = scriptedGateway(context, grantId, {
      observations: [
        {
          status: "finalized",
          transactionHash: `0x${"ee".repeat(32)}`,
          execution: {
            sender: ACCOUNT,
            calls: resolveCalls(definition, terms, "setup"),
            outcome: "success",
          },
        },
      ],
    });
    await drain(context, gateway.open);
    expect((await run(context, planId, "setup")).status).toBe("finalized");
    const plan = await context.pool.query("SELECT status FROM automation_plans WHERE id=$1", [
      planId,
    ]);
    expect(plan.rows[0].status).toBe("active");
    await context.pool.end();
  });

  it("fails closed when finalized calls are not the run's calls", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    const gateway = scriptedGateway(context, grantId, {
      observations: [
        {
          status: "finalized",
          transactionHash: `0x${"ee".repeat(32)}`,
          execution: { sender: ACCOUNT, calls: [], outcome: "success" },
        },
      ],
    });
    await drain(context, gateway.open);
    const row = await run(context, planId, "occurrence:0");
    expect([row.status, row.reason]).toEqual(["failed", "evidence_mismatch"]);
    await context.pool.end();
  });
});

describe.skipIf(!postgresAvailable)("claims across replicas", () => {
  let cluster: TestCluster;
  beforeAll(async () => {
    cluster = await startCluster();
  });
  afterAll(() => cluster?.stop());

  it("leases each run to exactly one replica until its lease expires", async () => {
    const clock = { now: START + 1 };
    const url = await cluster.database();
    const a = await testContext(url, clock, "replica-a");
    const b = await testContext(url, clock, "replica-b");
    const plans = [`0x${"a1".repeat(32)}`, `0x${"b2".repeat(32)}`];
    for (const id of plans) {
      await insertPlan(a, "active", id);
      await insertRun(a, id, "occurrence:0", "occurrence", 0);
    }
    const claims = await Promise.all([claimRun(a), claimRun(b), claimRun(a), claimRun(b)]);
    const won = claims.filter((claim) => claim !== null);
    expect(won).toHaveLength(2);
    expect(new Set(won.map((claim) => claim?.plan_id))).toEqual(new Set(plans));
    const owners = await a.pool.query(
      "SELECT lease_owner, generation FROM automation_runs ORDER BY plan_id",
    );
    expect(owners.rows.every((row) => row.generation === 1)).toBe(true);
    // Nothing is claimable again until a lease expires.
    expect(await claimRun(b)).toBeNull();
    clock.now += LEASE_SECONDS + 1;
    const reclaimed = await claimRun(b);
    expect(reclaimed?.generation).toBe(2);
    // The superseded holder's fenced writes no longer land.
    const stale = won.find((claim) => claim?.plan_id === reclaimed?.plan_id);
    const write = await a.pool.query(
      "UPDATE automation_runs SET reason='stale' WHERE plan_id=$1 AND run_key=$2 AND generation=$3",
      [stale?.plan_id, stale?.run_key, stale?.generation],
    );
    expect(write.rowCount).toBe(0);
    await a.pool.end();
    await b.pool.end();
  });
});
