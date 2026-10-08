import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { derivePlanPolicy } from "@oaath/automation";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type AutomationService, startAutomationService } from "../src/service.js";
import { ACCOUNT, APP_TOKEN, definition, testConfig } from "./support/fixture.js";
import { postgresAvailable, startCluster, type TestCluster } from "./support/postgres.js";

/** A stand-in issuer: records pushed requests and answers the token endpoint from a script. */
async function fakeIssuer() {
  const pushed: URLSearchParams[] = [];
  const token: { answer: { status: number; body: unknown } } = {
    answer: { status: 400, body: { error: "authorization_pending" } },
  };
  const server: Server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const form = new URLSearchParams(Buffer.concat(chunks).toString());
    response.setHeader("content-type", "application/json");
    if (request.url === "/oauth/par") {
      pushed.push(form);
      response.end(
        JSON.stringify({
          request_uri: `urn:ietf:params:oauth:request_uri:par-${pushed.length}`,
          expires_in: 600,
        }),
      );
      return;
    }
    if (request.url === "/oauth/token") {
      response.statusCode = token.answer.status;
      response.end(JSON.stringify(token.answer.body));
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, pushed, token, close: () => server.close() };
}

describe.skipIf(!postgresAvailable)("HTTP API", () => {
  let cluster: TestCluster;
  let issuer: Awaited<ReturnType<typeof fakeIssuer>>;
  let service: AutomationService;
  const call = async (
    method: string,
    path: string,
    token: string | null,
    body?: unknown,
    origin?: string,
  ) => {
    const response = await fetch(`${service.url}${path}`, {
      method,
      redirect: "manual",
      headers: {
        ...(token === null ? {} : { authorization: `Bearer ${token}` }),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(origin === undefined ? {} : { origin }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {}
    return { status: response.status, json, headers: response.headers };
  };
  const session = async (userId: string) =>
    (await call("POST", "/v1/sessions", APP_TOKEN, { userId, account: ACCOUNT })).json
      .token as string;
  const create = (token: string, key: string, budget = "1000") =>
    call("POST", "/v1/plans", token, {
      automation: definition.id,
      params: { budget },
      occurrences: 3,
      idempotencyKey: key,
    });

  beforeAll(async () => {
    cluster = await startCluster();
    issuer = await fakeIssuer();
    service = await startAutomationService(
      testConfig(await cluster.database(), { issuer: issuer.url }),
      {
        executors: 0,
        gateway: async () => {
          throw new Error("no_execution_in_http_tests");
        },
      },
    );
  });
  afterAll(async () => {
    await service?.close();
    issuer?.close();
    cluster?.stop();
  });

  it("issues sessions only to applications", async () => {
    expect((await call("POST", "/v1/sessions", "not-an-application-token", {})).status).toBe(401);
    expect((await call("GET", "/v1/plans", null)).json).toEqual({
      error: { code: "authentication_required" },
    });
    const created = await call("POST", "/v1/sessions", APP_TOKEN, {
      userId: "u1",
      account: ACCOUNT,
    });
    expect(created.status).toBe(200);
    expect(created.json).toMatchObject({ account: ACCOUNT, keyScope: "user" });
  });

  it("creates plans idempotently and isolates them per user", async () => {
    const alice = await session("alice");
    const first = await create(alice, "k1");
    expect(first.status).toBe(201);
    expect(first.json).toMatchObject({ status: "draft", automation: { id: definition.id } });
    const again = await create(alice, "k1");
    expect([again.status, again.json.id]).toEqual([200, first.json.id]);
    expect((await create(alice, "k1", "2000")).json.error.code).toBe("idempotency_conflict");
    expect((await create(alice, "k2", "0")).json.error.code).toBe("plan_param_out_of_bounds");
    const bob = await session("bob");
    expect((await call("GET", `/v1/plans/${first.json.id}`, bob)).status).toBe(404);
    expect((await call("GET", "/v1/plans", bob)).json.plans).toEqual([]);
    expect((await call("GET", `/v1/plans/${first.json.id}`, APP_TOKEN)).status).toBe(200);
  });

  it("pushes exactly the derived Grant for the plan's custodied signer", async () => {
    const alice = await session("alice");
    const plan = (await create(alice, "k-authorize")).json;
    const before = Math.floor(Date.now() / 1000);
    const authorized = await call("POST", `/v1/plans/${plan.id}/authorize`, alice, {
      returnTo: "http://localhost:5173/done",
    });
    expect(authorized.status).toBe(200);
    const pushed = issuer.pushed.at(-1) as URLSearchParams;
    expect(authorized.json.authorizationUrl).toBe(
      `${issuer.url}/authorize?client_id=automation-test-client&request_uri=${encodeURIComponent(
        "urn:ietf:params:oauth:request_uri:par-" + issuer.pushed.length,
      )}`,
    );
    expect(pushed.get("redirect_uri")).toBe("http://127.0.0.1:4317/v1/oauth/callback");
    expect(pushed.get("code_challenge_method")).toBe("S256");
    const [detail] = JSON.parse(pushed.get("authorization_details") as string);
    const current = authorized.json.plan;
    expect(current.status).toBe("awaiting_consent");
    expect(detail.signer).toEqual({
      version: "oaath.operator-credential-profile/v1",
      kind: "ecdsa",
      address: current.signer,
    });
    expect(detail.expires_at).toBe(current.terms.schedule.endAt);
    expect(detail.policy).toEqual(current.permission);
    expect(detail.policy.validAfter).toBeGreaterThanOrEqual(before);
    expect(detail.policy).toEqual(
      derivePlanPolicy(definition, current.terms, detail.policy.validAfter),
    );
    // The signer is sealed at rest: no stored column holds the private key in the clear.
    const signers = await service.context.pool.query(
      "SELECT sealed::text AS sealed FROM automation_signers",
    );
    expect(signers.rows).toHaveLength(1);
    expect(signers.rows[0].sealed).not.toMatch(/privateKey/u);
    // A second plan for the same user shares the user-scoped signer.
    const other = (await create(alice, "k-authorize-2")).json;
    const second = await call("POST", `/v1/plans/${other.id}/authorize`, alice, {});
    expect(second.json.plan.signer).toBe(current.signer);
  });

  it("answers the issuer's redirect from PostgreSQL", async () => {
    const alice = await session("alice");
    const plan = (await create(alice, "k-callback")).json;
    await call("POST", `/v1/plans/${plan.id}/authorize`, alice, {
      returnTo: "http://localhost:5173/done",
    });
    const state = (issuer.pushed.at(-1) as URLSearchParams).get("state") as string;
    expect((await call("GET", "/v1/oauth/callback?state=unknown&code=c", null)).status).toBe(400);
    const wrongIssuer = await call(
      "GET",
      `/v1/oauth/callback?${new URLSearchParams({ state, code: "c", iss: "http://evil" })}`,
      null,
    );
    expect(wrongIssuer.status).toBe(303);
    expect(wrongIssuer.headers.get("location")).toContain("automation_status=invalid");
    // A member's request waits for the account root: the code is kept, not re-authorized.
    const pending = await call(
      "GET",
      `/v1/oauth/callback?${new URLSearchParams({ state, code: "c", iss: issuer.url })}`,
      null,
    );
    expect(pending.headers.get("location")).toBe(
      `http://localhost:5173/done?automation_plan=${plan.id}&automation_status=pending`,
    );
    const row = await service.context.pool.query(
      "SELECT status, next_consent_at FROM automation_plans WHERE id=$1",
      [plan.id],
    );
    expect(row.rows[0].status).toBe("awaiting_consent");
    expect(row.rows[0].next_consent_at).not.toBeNull();
    // The root declines.
    issuer.token.answer = { status: 400, body: { error: "access_denied" } };
    const declined = await call(
      "GET",
      `/v1/oauth/callback?${new URLSearchParams({ state, code: "c", iss: issuer.url })}`,
      null,
    );
    expect(declined.headers.get("location")).toContain("automation_status=declined");
    expect((await call("GET", `/v1/plans/${plan.id}`, alice)).json).toMatchObject({
      status: "draft",
      diagnostic: "consent_declined",
    });
  });

  it("refuses foreign browser origins and foreign return targets", async () => {
    const alice = await session("alice");
    expect((await call("GET", "/v1/plans", alice, undefined, "https://evil.example")).status).toBe(
      403,
    );
    const allowed = await call("GET", "/v1/plans", alice, undefined, "http://localhost:5173");
    expect(allowed.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    const plan = (await create(alice, "k-return")).json;
    const refused = await call("POST", `/v1/plans/${plan.id}/authorize`, alice, {
      returnTo: "https://evil.example/steal",
    });
    expect(refused.json.error.code).toBe("return_to_invalid");
  });

  it("cancels a plan that never ran without touching the chain", async () => {
    const alice = await session("alice");
    const plan = (await create(alice, "k-cancel")).json;
    const cancelled = await call("POST", `/v1/plans/${plan.id}/cancel`, alice, {});
    expect(cancelled.json.status).toBe("cancelled");
    expect((await call("POST", `/v1/plans/${plan.id}/pause`, alice, {})).json.error.code).toBe(
      "plan_not_active",
    );
  });

  it("lists runs without a slot beside the occurrences", async () => {
    const alice = await session("alice");
    const plan = (await create(alice, "k-runs")).json;
    for (const [key, kind, slot] of [
      ["setup", "setup", null],
      ["occurrence:0", "occurrence", 0],
    ] as const)
      await service.context.pool.query(
        "INSERT INTO automation_runs(plan_id,run_key,kind,slot,scheduled_at,status) VALUES($1,$2,$3,$4,1,'due')",
        [plan.id, key, kind, slot],
      );
    const runs = (await call("GET", `/v1/plans/${plan.id}/runs`, alice)).json.runs;
    expect(runs.map((run: { kind: string }) => run.kind)).toEqual(["setup", "occurrence"]);
    const next = (await call("GET", `/v1/plans/${plan.id}/runs?after=0`, alice)).json.runs;
    expect(next.map((run: { kind: string }) => run.kind)).toEqual(["setup"]);
  });
});
