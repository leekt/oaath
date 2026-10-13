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
  paymasterPayer,
  processRun,
  type RunLane,
} from "../src/executor.js";
import { tick } from "../src/scheduler.js";
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
  const at = START + (slot ?? 0) * 3600;
  await context.pool.query(
    `INSERT INTO automation_runs(plan_id,run_key,kind,slot,lane,scheduled_at,closes_at,status,next_attempt_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,'due',$6)`,
    [planId, key, kind, slot, slot ?? 0, at, slot === null ? null : at + 600],
  );
}

/** One distinct operation hash per lane, so no lane can pass for another. */
const laneHash = (lane: number) =>
  (lane === 0
    ? `0x${"cd".repeat(32)}`
    : `0x${lane.toString(16).padStart(64, "e")}`) as `0x${string}`;
const laneKey = (lane: RunLane) => (lane === null ? 0 : Number(lane.nonceKey));
/** Included on chain, not final, with this UserOperation outcome. */
const included = (inclusion: "success" | "reverted"): Observation => ({
  status: "pending",
  transactionHash: `0x${"ee".repeat(32)}`,
  inclusion,
  execution: null,
});
const planStatus = async (context: ServiceContext, planId: string) =>
  (
    await context.pool.query("SELECT status, diagnostic FROM automation_plans WHERE id=$1", [
      planId,
    ])
  ).rows[0];
const runKeys = async (context: ServiceContext, planId: string) =>
  (
    await context.pool.query(
      "SELECT run_key, lane, status FROM automation_runs WHERE plan_id=$1 ORDER BY run_key",
      [planId],
    )
  ).rows;

/** Journals like the SDK, then answers observations from a script. */
function scriptedGateway(
  context: ServiceContext,
  grantId: string,
  script: { observations: Observation[]; failSend?: "before_journal" | "after_journal" },
) {
  const counts = { sends: 0, observations: 0 };
  /** The lane key of every send and every observation, in order. */
  const lanes = { sends: [] as number[], observations: [] as number[] };
  const journal = createOperationStore(context.pool);
  const hash = laneHash(0);
  const gateway: OperationGateway = {
    async send(_calls, lane) {
      counts.sends += 1;
      lanes.sends.push(laneKey(lane));
      if (script.failSend === "before_journal") throw new Error("bundler_unavailable");
      const hash = laneHash(laneKey(lane));
      const committed = await journal.compareAndSwap({
        key: {
          grantId,
          chainId: 31337,
          kind: "execution",
          ...(lane === null ? {} : { lane: laneKey(lane) }),
        },
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
    async observe(id, lane) {
      // A run observes only its own lane's operation.
      expect(id).toBe(laneHash(laneKey(lane)));
      counts.observations += 1;
      lanes.observations.push(laneKey(lane));
      return (
        script.observations.shift() ?? { status: "pending", transactionHash: null, execution: null }
      );
    },
    async close() {},
  };
  return { counts, lanes, open: async () => gateway, hash };
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

describe("paymasterPayer", () => {
  const endpoints = {
    rpcUrl: "http://rpc",
    bundlerUrl: "http://bundler",
    bundlerApiKey: null,
    relayPaysGas: false,
  };

  it("sends the configured API key as the ERC-7677 context, else an empty one", () => {
    expect(
      paymasterPayer({ ...endpoints, paymasterUrl: "http://pm", paymasterApiKey: "pm-key" }),
    ).toEqual({ kind: "paymaster-service", url: "http://pm", context: { apiKey: "pm-key" } });
    expect(
      paymasterPayer({ ...endpoints, paymasterUrl: "http://pm", paymasterApiKey: null }),
    ).toEqual({ kind: "paymaster-service", url: "http://pm", context: {} });
    expect(paymasterPayer({ ...endpoints, paymasterUrl: null, paymasterApiKey: null })).toBeNull();
    expect(paymasterPayer(undefined)).toBeNull();
  });
});

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

  it("sends the next slot on its own lane while the previous one is included but not final", async () => {
    const clock = { now: START + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    const included: Observation = {
      status: "pending",
      transactionHash: `0x${"ee".repeat(32)}`,
      execution: null,
    };
    const gateway = scriptedGateway(context, grantId, { observations: [included, included] });
    await drain(context, gateway.open);
    expect((await run(context, planId, "occurrence:0")).status).toBe("observed");

    // Slot 1 comes due while slot 0 still waits for finality.
    await insertRun(context, planId, "occurrence:1", "occurrence", 1);
    clock.now = START + 3600 + 1;
    await drain(context, gateway.open);
    const [zero, one] = [
      await run(context, planId, "occurrence:0"),
      await run(context, planId, "occurrence:1"),
    ];
    expect([zero.status, zero.op_hash]).toEqual(["observed", laneHash(0)]);
    expect([one.status, one.op_hash, one.lane]).toEqual(["submitted", laneHash(1), 1]);
    expect(gateway.lanes.sends).toEqual([0, 1]);

    // Observation retries on both lanes submit nothing new.
    for (let pass = 0; pass < 4; pass += 1) {
      clock.now += 120;
      await drain(context, gateway.open);
    }
    expect(gateway.lanes.sends).toEqual([0, 1]);
    expect(new Set(gateway.lanes.observations)).toEqual(new Set([0, 1]));
    expect((await run(context, planId, "occurrence:0")).op_hash).toBe(laneHash(0));
    expect((await run(context, planId, "occurrence:1")).op_hash).toBe(laneHash(1));
    await context.pool.end();
  });

  it("binds a journaled identity only to the prepared run on its own lane", async () => {
    const clock = { now: START + 3600 + 1 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "active");
    await insertRun(context, planId, "occurrence:0", "occurrence", 0);
    await insertRun(context, planId, "occurrence:1", "occurrence", 1);
    await context.pool.query("UPDATE automation_runs SET status='prepared', calls='[]'");
    const gateway = await scriptedGateway(context, grantId, { observations: [] }).open();
    // No run is prepared on lane 7: its identity is refused and nothing is journaled.
    await expect(gateway.send([], { id: "occurrence:7", nonceKey: 7n })).rejects.toThrow(
      "journal_refused",
    );
    await gateway.send([], { id: "occurrence:1", nonceKey: 1n });
    expect((await run(context, planId, "occurrence:0")).op_hash).toBeNull();
    expect((await run(context, planId, "occurrence:1")).op_hash).toBe(laneHash(1));
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
    await (await first.open()).send([], null);
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
    await expect((await gateway.open()).send([], null)).rejects.toThrow("journal_refused");
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

  it("activates on an included, successful setup and sends slot 0 on its own lane before setup finality", async () => {
    const clock = { now: START - 50 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "authorized");
    const gateway = scriptedGateway(context, grantId, { observations: [included("success")] });
    await tick(context);
    await drain(context, gateway.open);
    expect((await run(context, planId, "setup")).status).toBe("observed");
    expect((await planStatus(context, planId)).status).toBe("active");

    clock.now = START + 1;
    await tick(context);
    await drain(context, gateway.open);
    expect(await runKeys(context, planId)).toEqual([
      { run_key: "occurrence:0", lane: 1, status: "submitted" },
      { run_key: "setup", lane: 0, status: "observed" },
    ]);
    expect((await run(context, planId, "occurrence:0")).op_hash).toBe(laneHash(1));
    expect(gateway.lanes.sends).toEqual([0, 1]);
    await context.pool.end();
  });

  it("admits no occurrence for a reverted setup and fails the plan when it ends", async () => {
    const clock = { now: START - 50 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "authorized");
    const terms = (
      await context.pool.query("SELECT terms FROM automation_plans WHERE id=$1", [planId])
    ).rows[0].terms;
    const gateway = scriptedGateway(context, grantId, {
      observations: [
        included("reverted"),
        {
          status: "finalized",
          transactionHash: `0x${"ee".repeat(32)}`,
          execution: {
            sender: ACCOUNT,
            calls: resolveCalls(definition, terms, "setup"),
            outcome: "reverted",
          },
        },
      ],
    });
    await tick(context);
    await drain(context, gateway.open);
    clock.now = START + 1;
    await tick(context);
    expect((await planStatus(context, planId)).status).toBe("authorized");
    expect((await runKeys(context, planId)).map((row) => row.run_key)).toEqual(["setup"]);
    clock.now += 120;
    await drain(context, gateway.open);
    await tick(context);
    expect(await planStatus(context, planId)).toEqual({
      status: "failed",
      diagnostic: "setup_failed",
    });
    expect(await runKeys(context, planId)).toEqual([
      { run_key: "setup", lane: 0, status: "failed" },
    ]);
    expect(gateway.lanes.sends).toEqual([0]);
    await context.pool.end();
  });

  it("fails an activated plan whose included setup is later dropped", async () => {
    const clock = { now: START - 50 };
    const context = await testContext(await cluster.database(), clock);
    const { planId, grantId } = await insertPlan(context, "authorized");
    const gateway = scriptedGateway(context, grantId, {
      observations: [
        included("success"),
        { status: "dropped", transactionHash: null, execution: null },
      ],
    });
    await tick(context);
    await drain(context, gateway.open);
    expect((await planStatus(context, planId)).status).toBe("active");
    clock.now += 120;
    await drain(context, gateway.open);
    expect((await planStatus(context, planId)).status).toBe("failed");
    clock.now = START + 1;
    await tick(context);
    expect((await runKeys(context, planId)).map((row) => row.run_key)).toEqual(["setup"]);
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

  it("sends setup and slot 0 exactly once across two replicas when setup is only included", async () => {
    const clock = { now: START - 50 };
    const url = await cluster.database();
    const a = await testContext(url, clock, "replica-a");
    const b = await testContext(url, clock, "replica-b");
    const { planId, grantId } = await insertPlan(a, "authorized");
    const gateway = scriptedGateway(a, grantId, { observations: [included("success")] });
    for (const at of [START - 50, START + 1, START + 122, START + 243]) {
      clock.now = at;
      await Promise.all([tick(a), tick(b)]);
      await Promise.all(
        [a, b, a, b].map(async (replica) => {
          const claimed = await claimRun(replica);
          if (claimed !== null) await processRun(replica, claimed, gateway.open);
        }),
      );
    }
    expect([...gateway.lanes.sends].sort()).toEqual([0, 1]);
    expect(await runKeys(a, planId)).toEqual([
      { run_key: "occurrence:0", lane: 1, status: "submitted" },
      { run_key: "setup", lane: 0, status: "observed" },
    ]);
    await a.pool.end();
    await b.pool.end();
  });

  it("sends each open slot of one plan exactly once across two replicas", async () => {
    const clock = { now: START + 3600 + 1 };
    const url = await cluster.database();
    const a = await testContext(url, clock, "replica-a");
    const b = await testContext(url, clock, "replica-b");
    const { planId, grantId } = await insertPlan(a, "active");
    // Slot 0 is still inside its window here only because closes_at is widened.
    await insertRun(a, planId, "occurrence:0", "occurrence", 0);
    await insertRun(a, planId, "occurrence:1", "occurrence", 1);
    await a.pool.query("UPDATE automation_runs SET closes_at=$1", [START + 7200]);
    const gateway = scriptedGateway(a, grantId, { observations: [] });
    for (let pass = 0; pass < 3; pass += 1) {
      await Promise.all(
        [a, b, a, b].map(async (replica) => {
          const claimed = await claimRun(replica);
          if (claimed !== null) await processRun(replica, claimed, gateway.open);
        }),
      );
      clock.now += LEASE_SECONDS + 1;
    }
    expect([...gateway.lanes.sends].sort()).toEqual([0, 1]);
    const rows = await a.pool.query(
      "SELECT run_key, op_hash FROM automation_runs WHERE plan_id=$1 ORDER BY run_key",
      [planId],
    );
    expect(rows.rows).toEqual([
      { run_key: "occurrence:0", op_hash: laneHash(0) },
      { run_key: "occurrence:1", op_hash: laneHash(1) },
    ]);
    await a.pool.end();
    await b.pool.end();
  });
});
