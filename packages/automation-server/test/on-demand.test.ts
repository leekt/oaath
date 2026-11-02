/**
 * On-demand plans against real PostgreSQL: request admission over HTTP, the
 * per-chain lane rule, the executor sending exactly the persisted calls once,
 * and the plan lifecycle without setup or cancel calls. Authorization itself
 * is the unchanged OAuth path; these tests stand in for it by writing the
 * approved policy and Grant id the way adoption leaves them.
 */
import { createPlanTerms, derivePlanPolicy, hashPlanTerms } from "@oaath/automation";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ServiceContext } from "../src/context.js";
import { claimRun, type Observation, type OperationGateway, processRun } from "../src/executor.js";
import { admitRequest, tick } from "../src/scheduler.js";
import { type AutomationService, startAutomationService } from "../src/service.js";
import { createOperationStore } from "../src/store.js";
import {
  ACCOUNT,
  APP_TOKEN,
  DEPLOY,
  DEPLOYER,
  onDemandDefinition,
  testConfig,
  testContext,
  VAULT,
} from "./support/fixture.js";
import { postgresAvailable, startCluster, type TestCluster } from "./support/postgres.js";

const START = 1_900_000_000;
const DAY = 86400;
const deployCall = (salt = "00") => ({
  to: DEPLOYER,
  data: `${DEPLOY}${salt.repeat(32)}`,
  value: "0",
});

/** Stands in for OAuth adoption: the approved policy and the Grant, then admission activates. */
async function authorize(context: ServiceContext, planId: string, grantId: string) {
  const row = (await context.pool.query("SELECT terms FROM automation_plans WHERE id=$1", [planId]))
    .rows[0];
  const policy = derivePlanPolicy(onDemandDefinition, row.terms, context.now());
  await context.pool.query(
    "UPDATE automation_plans SET status='authorized', permission=$2, grant_id=$3 WHERE id=$1",
    [planId, policy, grantId],
  );
  await tick(context);
}

describe.skipIf(!postgresAvailable)("on-demand plans", () => {
  let cluster: TestCluster;
  beforeAll(async () => {
    cluster = await startCluster();
  });
  afterAll(() => cluster?.stop());

  describe("HTTP admission", () => {
    const clock = { ms: START * 1000 };
    let service: AutomationService;
    const call = async (method: string, path: string, token: string, body?: unknown) => {
      const response = await fetch(`${service.url}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      return { status: response.status, json: (await response.json()) as any };
    };
    const session = async () =>
      (await call("POST", "/v1/sessions", APP_TOKEN, { userId: "alice", account: ACCOUNT })).json
        .token as string;
    const submit = (token: string, planId: string, body: unknown) =>
      call("POST", `/v1/plans/${planId}/operations`, token, body);
    const code = (response: { json: any }) => response.json.error?.code;

    beforeAll(async () => {
      service = await startAutomationService(testConfig(await cluster.database()), {
        executors: 0,
        clock: () => clock.ms,
        gateway: async () => {
          throw new Error("no_execution_in_admission_tests");
        },
      });
    });
    afterAll(() => service?.close());

    it("admits exact on-policy calls once per key, one lane per chain until install", async () => {
      const alice = await session();
      const created = await call("POST", "/v1/plans", alice, {
        automation: onDemandDefinition.id,
        validFor: 7 * DAY,
        idempotencyKey: "plan-1",
      });
      expect(created.status).toBe(201);
      expect(created.json.terms).toMatchObject({
        kind: "on-demand",
        chains: [31337, 31338],
        startAt: START,
        endAt: START + 7 * DAY,
      });
      const planId = created.json.id as string;
      const body = { chainId: 31337, calls: [deployCall()], idempotencyKey: "op-1" };
      // Before the root approves, nothing is admitted.
      expect(code(await submit(alice, planId, body))).toBe("plan_not_active");
      await authorize(service.context, planId, "grant-od-1");
      expect((await call("GET", `/v1/plans/${planId}`, alice)).json.status).toBe("active");

      const first = await submit(alice, planId, body);
      expect(first.status).toBe(201);
      expect(first.json.run).toMatchObject({
        kind: "request",
        chainId: 31337,
        lane: 0,
        status: "due",
        operation: null,
        nonce: null,
        transactionHash: null,
        reason: null,
      });
      expect(first.json.run.id).toMatch(/^request:[0-9a-f]{64}$/u);
      // The same key and body is the same run; another body under it conflicts.
      const replay = await submit(alice, planId, body);
      expect([replay.status, replay.json.run]).toEqual([200, first.json.run]);
      const conflict = await submit(alice, planId, { ...body, calls: [deployCall("11")] });
      expect([conflict.status, code(conflict)]).toEqual([409, "idempotency_conflict"]);
      const read = await call(
        "GET",
        `/v1/plans/${planId}/runs/${encodeURIComponent(first.json.run.id)}`,
        alice,
      );
      expect(read.json.run).toEqual(first.json.run);
      expect(code(await call("GET", `/v1/plans/${planId}/runs/request%3Anone`, alice))).toBe(
        "run_not_found",
      );

      // The install is not yet included on 31337: the next request there waits.
      const second = { chainId: 31337, calls: [deployCall("22")], idempotencyKey: "op-2" };
      const busy = await submit(alice, planId, second);
      expect([busy.status, code(busy)]).toEqual([429, "lanes_busy"]);
      // Another of the plan's chains installs independently.
      const other = await submit(alice, planId, {
        ...second,
        chainId: 31338,
        idempotencyKey: "op-3",
      });
      expect([other.status, other.json.run.chainId, other.json.run.lane]).toEqual([201, 31338, 0]);

      // Once the install is included on 31337, requests take lanes 1..maxOpenSlots there.
      await service.context.pool.query(
        "UPDATE automation_runs SET status='observed' WHERE plan_id=$1 AND run_key=$2",
        [planId, first.json.run.id],
      );
      const lanes: number[] = [];
      for (const salt of ["31", "32", "33", "34"]) {
        const admitted = await submit(alice, planId, {
          chainId: 31337,
          calls: [deployCall(salt)],
          idempotencyKey: `lane-${salt}`,
        });
        lanes.push(admitted.json.run.lane);
      }
      expect(lanes).toEqual([1, 2, 3, 4]);
      expect(code(await submit(alice, planId, second))).toBe("lanes_busy");
      // A closed lane is the lowest free one again.
      await service.context.pool.query(
        "UPDATE automation_runs SET status='finalized' WHERE plan_id=$1 AND chain_id=31337 AND lane=2",
        [planId],
      );
      expect((await submit(alice, planId, second)).json.run.lane).toBe(2);

      const runs = (await call("GET", `/v1/plans/${planId}/runs`, alice)).json.runs;
      expect(runs).toHaveLength(7);
      expect(runs[0]).toHaveProperty("nonce");
    });

    it("refuses calls, chains and callers the plan does not allow", async () => {
      const alice = await session();
      const planId = (
        await call("POST", "/v1/plans", alice, {
          automation: onDemandDefinition.id,
          validFor: DAY,
          idempotencyKey: "plan-2",
        })
      ).json.id as string;
      await authorize(service.context, planId, "grant-od-2");
      const refused = async (calls: unknown, chainId = 31337) =>
        submit(alice, planId, { chainId, calls, idempotencyKey: `bad-${Math.random()}` });
      const expectRefusal = async (
        response: Promise<{ status: number; json: any }>,
        code: string,
      ) => expect(await response).toMatchObject({ status: 422, json: { error: { code } } });
      await expectRefusal(refused([{ ...deployCall(), to: VAULT }]), "call_not_permitted");
      await expectRefusal(refused([{ ...deployCall(), data: "0xa9059cbb" }]), "call_not_permitted");
      await expectRefusal(refused([{ ...deployCall(), value: "1" }]), "value_limit_exceeded");
      await expectRefusal(refused([{ to: VAULT, data: "0x", value: "6" }]), "value_limit_exceeded");
      // One to three bytes of calldata have no selector; the account would revert them.
      await expectRefusal(refused([{ to: VAULT, data: "0x00", value: "0" }]), "call_not_permitted");
      // One off-policy call refuses the whole operation.
      await expectRefusal(
        refused([deployCall(), { ...deployCall(), to: VAULT }]),
        "call_not_permitted",
      );
      await expectRefusal(refused([deployCall()], 1), "chain_not_in_plan");
      await expectRefusal(refused([{ ...deployCall(), extra: 1 }]), "calls_invalid");
      await expectRefusal(refused([]), "calls_invalid");
      // Empty calldata is selector 0x00000000: a plain transfer within its limit fits.
      const transfer = await refused([{ to: VAULT, data: "0x", value: "5" }]);
      expect(transfer.status).toBe(201);
      // An application credential acts for no user and may not submit.
      expect(code(await submit(APP_TOKEN, planId, { chainId: 31337 }))).toBe(
        "user_session_required",
      );
      // A paused plan admits nothing; past its end the plan refuses as expired.
      await call("POST", `/v1/plans/${planId}/pause`, alice, {});
      expect(code(await refused([deployCall()], 31338))).toBe("plan_not_active");
      await call("POST", `/v1/plans/${planId}/resume`, alice, {});
      clock.ms = (START + DAY) * 1000;
      const late = await submit(await session(), planId, {
        chainId: 31338,
        calls: [deployCall()],
        idempotencyKey: "late",
      });
      expect([late.status, code(late)]).toEqual([409, "plan_expired"]);
      clock.ms = START * 1000;
    });

    it("refuses requests on a scheduled plan", async () => {
      const alice = await session();
      const planId = (
        await call("POST", "/v1/plans", alice, {
          automation: "recurring.v1",
          params: { budget: "1" },
          occurrences: 2,
          idempotencyKey: "plan-3",
        })
      ).json.id as string;
      const response = await submit(alice, planId, {
        chainId: 31337,
        calls: [deployCall()],
        idempotencyKey: "op",
      });
      expect([response.status, code(response)]).toEqual([409, "plan_not_on_demand"]);
    });
  });

  describe("execution and lifecycle", () => {
    async function activePlan(context: ServiceContext, planId: `0x${string}`, grantId: string) {
      const terms = createPlanTerms(onDemandDefinition, {
        planId,
        account: ACCOUNT,
        now: START,
        validFor: DAY,
      });
      await context.pool.query(
        `INSERT INTO automation_plans(id,app_id,user_id,account,key_scope,automation_id,definition,terms,plan_hash,
           creation_key,input_digest,status,next_at,created_at)
         VALUES($1,'app','user',$2,'user',$3,$4,$5,$6,$1,'d','draft',$7,$7)`,
        [
          planId,
          ACCOUNT,
          onDemandDefinition.id,
          onDemandDefinition,
          terms,
          hashPlanTerms(terms),
          START,
        ],
      );
      await authorize(context, planId, grantId);
    }

    /** Journals like the SDK on the run's own chain and lane, then answers from a script. */
    function scriptedGateway(
      context: ServiceContext,
      grantId: string,
      observations: Observation[],
    ) {
      const sent: { chainId: number; calls: unknown; lane: number }[] = [];
      const journal = createOperationStore(context.pool);
      const hash = `0x${"cd".repeat(32)}` as const;
      let observed = 0;
      const open = async (_plan: unknown, chainId: number): Promise<OperationGateway> => ({
        async send(calls, lane) {
          sent.push({ chainId, calls, lane: lane === null ? 0 : Number(lane.nonceKey) });
          const committed = await journal.compareAndSwap({
            key: {
              grantId,
              chainId,
              kind: "execution",
              ...(lane === null ? {} : { lane: Number(lane.nonceKey) }),
            },
            expectedStoreRevision: null,
            next: {
              version: "oaath.operation-store-record/v1",
              storeRevision: 1,
              updatedAt: START,
              value: { state: "prepared", identity: { userOperationHash: hash, nonce: "42" } },
            },
            expectedArchiveAbsentUserOperationHash: hash,
            archive: null,
          });
          if (!committed) throw new Error("journal_refused");
          return hash;
        },
        async observe() {
          observed += 1;
          return (
            observations.shift() ?? { status: "pending", transactionHash: null, execution: null }
          );
        },
        async close() {},
      });
      return { sent, open, observations: () => observed, hash };
    }

    it("sends exactly the persisted calls once on the run's chain, then only observes", async () => {
      const clock = { now: START + 10 };
      const context = await testContext(await cluster.database(), clock);
      const planId = `0x${"ad".repeat(32)}` as const;
      await activePlan(context, planId, "grant-x");
      const calls = [deployCall("aa"), { to: VAULT, data: "0x", value: "5" }];
      const { run } = await admitRequest(context, planId, {
        chainId: 31338,
        calls,
        idempotencyKey: "deploy-1",
      });
      const gateway = scriptedGateway(context, "grant-x", []);
      for (let round = 0; round < 3; round += 1) {
        const claimed = await claimRun(context);
        if (claimed === null) break;
        await processRun(context, claimed, gateway.open);
        clock.now += 120;
      }
      expect(gateway.sent).toEqual([
        {
          chainId: 31338,
          lane: 0,
          calls: calls.map((call) => ({ target: call.to, value: call.value, data: call.data })),
        },
      ]);
      expect(gateway.observations()).toBeGreaterThanOrEqual(2);
      const stored = (
        await context.pool.query("SELECT * FROM automation_runs WHERE run_key=$1", [run.run_key])
      ).rows[0];
      expect(stored).toMatchObject({
        status: "submitted",
        op_hash: gateway.hash,
        op_nonce: "42",
        chain_id: 31338,
      });
      // Finalized with exactly the persisted calls: the run is final, the plan stays active.
      const final = scriptedGateway(context, "grant-x", [
        {
          status: "finalized",
          transactionHash: `0x${"ee".repeat(32)}`,
          execution: {
            sender: ACCOUNT,
            calls: calls.map((call) => ({ target: call.to, value: call.value, data: call.data })),
            outcome: "success",
          },
        },
      ]);
      clock.now += 120;
      await processRun(context, (await claimRun(context)) as never, final.open);
      expect(final.sent).toEqual([]);
      const done = (
        await context.pool.query(
          "SELECT r.status, p.status AS plan FROM automation_runs r JOIN automation_plans p ON p.id=r.plan_id",
        )
      ).rows;
      expect(done).toEqual([{ status: "finalized", plan: "active" }]);
      await context.pool.end();
    });

    it("never journals a request's identity onto another chain's run", async () => {
      const clock = { now: START + 10 };
      const context = await testContext(await cluster.database(), clock);
      const planId = `0x${"ae".repeat(32)}` as const;
      await activePlan(context, planId, "grant-y");
      await admitRequest(context, planId, {
        chainId: 31337,
        calls: [deployCall()],
        idempotencyKey: "a",
      });
      const claimed = (await claimRun(context)) as NonNullable<
        Awaited<ReturnType<typeof claimRun>>
      >;
      await context.pool.query("UPDATE automation_runs SET status='prepared', calls='[]'");
      // An SDK identity journaled for chain 31338 claims no run there and is refused.
      const other = scriptedGateway(context, "grant-y", []);
      await expect((await other.open(null, 31338)).send([], null)).rejects.toThrow(
        "journal_refused",
      );
      expect(claimed.chain_id).toBe(31337);
      await context.pool.end();
    });

    it("activates without setup, cancels without calls, and expires at the Grant end", async () => {
      const clock = { now: START + 10 };
      const context = await testContext(await cluster.database(), clock);
      const planId = `0x${"af".repeat(32)}` as const;
      await activePlan(context, planId, "grant-z");
      const status = async () =>
        (await context.pool.query("SELECT status FROM automation_plans WHERE id=$1", [planId]))
          .rows[0].status;
      expect(await status()).toBe("active");
      expect((await context.pool.query("SELECT * FROM automation_runs")).rows).toEqual([]);
      await admitRequest(context, planId, {
        chainId: 31337,
        calls: [deployCall()],
        idempotencyKey: "a",
      });
      // Past the end an open run keeps the plan active until it closes.
      clock.now = START + DAY;
      await tick(context);
      expect(await status()).toBe("active");
      await context.pool.query("UPDATE automation_runs SET status='finalized'");
      clock.now += 10;
      await tick(context);
      expect(await status()).toBe("expired");

      const second = `0x${"b0".repeat(32)}` as const;
      clock.now = START + 10;
      await activePlan(context, second, "grant-w");
      await admitRequest(context, second, {
        chainId: 31337,
        calls: [deployCall()],
        idempotencyKey: "b",
      });
      await context.pool.query("UPDATE automation_runs SET status='submitted' WHERE plan_id=$1", [
        second,
      ]);
      await context.pool.query("UPDATE automation_plans SET status='cancelling' WHERE id=$1", [
        second,
      ]);
      await expect(
        admitRequest(context, second, {
          chainId: 31338,
          calls: [deployCall()],
          idempotencyKey: "c",
        }),
      ).rejects.toMatchObject({ code: "plan_not_active" });
      await tick(context);
      const cancelling = await context.pool.query(
        "SELECT status FROM automation_plans WHERE id=$1",
        [second],
      );
      expect(cancelling.rows[0].status).toBe("cancelling");
      await context.pool.query("UPDATE automation_runs SET status='finalized' WHERE plan_id=$1", [
        second,
      ]);
      await tick(context);
      const runs = await context.pool.query("SELECT kind FROM automation_runs WHERE plan_id=$1", [
        second,
      ]);
      expect(runs.rows).toEqual([{ kind: "request" }]);
      expect(
        (await context.pool.query("SELECT status FROM automation_plans WHERE id=$1", [second]))
          .rows[0].status,
      ).toBe("cancelled");
      await context.pool.end();
    });
  });
});
