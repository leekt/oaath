/**
 * PostgreSQL relay proof: row-locked one-time transitions under real
 * concurrency, on independent connections.
 *
 * Requires `OAATH_REQUIRE_POSTGRES=1`; skipped otherwise.
 *
 * @author taek <leekt216@gmail.com>
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OAATH_RELAY_POSTGRES_SCHEMA_VERSION } from "../src/store/postgres/schema.js";
import {
  approve,
  CLIENT_TOKEN,
  CODE_VERIFIER,
  claim,
  consume,
  createRequest,
  createTestClock,
  expectFailure,
  expectOk,
  get,
  OWNER_TOKEN,
  post,
  REDIRECT_URI,
} from "./support.js";
import {
  createPostgresFixture,
  createPostgresHarness,
  type PostgresFixture,
  requirePostgres,
} from "./support-postgres.js";

(requirePostgres ? describe : describe.skip)("PostgreSQL relay store", () => {
  let fixture: PostgresFixture;

  beforeAll(async () => {
    fixture = await createPostgresFixture();
  });

  afterAll(async () => {
    await fixture.end();
  });

  it("creates exactly one current schema version", async () => {
    const pool = fixture.createPool();
    const rows = await pool.query("SELECT schema_id, version FROM oaath_relay_schema_v1");
    expect(rows.rows).toEqual([
      { schema_id: "oaath", version: OAATH_RELAY_POSTGRES_SCHEMA_VERSION },
    ]);
  });

  it("round-trips the full authorization journey", async () => {
    const harness = createPostgresHarness(fixture);
    const created = await createRequest(harness);
    const state = await expectOk<{ requestId: string; expiresAt: number; expired: boolean }>(
      await harness.handler(get(`/authorization/requests/${created.requestId}`, OWNER_TOKEN)),
      200,
    );
    // bigint columns must survive the round trip exactly.
    expect(state).toMatchObject({
      requestId: created.requestId,
      expiresAt: created.expiresAt,
      expired: false,
    });

    const decision = await approve(harness, created.requestId, '{"grant":"pg"}');
    const consumed = await expectOk<{ artifactId: string }>(
      await consume(harness, decision.code),
      200,
    );
    const claimed = await expectOk<{ artifact: string }>(
      await claim(harness, consumed.artifactId),
      200,
    );
    expect(claimed.artifact).toBe('{"grant":"pg"}');
    await harness.shutdown();
  });

  it("releases a code once under concurrent consumes on independent stores", async () => {
    const clock = createTestClock();
    const issuing = createPostgresHarness(fixture, clock);
    const created = await createRequest(issuing);
    const decision = await approve(issuing, created.requestId);

    // Four workers, four pools, one row.
    const workers = [
      createPostgresHarness(fixture, clock),
      createPostgresHarness(fixture, clock),
      createPostgresHarness(fixture, clock),
      createPostgresHarness(fixture, clock),
    ];
    const responses = await Promise.all(workers.map((worker) => consume(worker, decision.code)));
    expect(responses.map((response) => response.status).sort()).toEqual([200, 409, 409, 409]);

    const claims = await Promise.all(workers.map((worker) => claim(worker, decision.artifactId)));
    expect(claims.map((response) => response.status).sort()).toEqual([200, 409, 409, 409]);
  });

  it("keeps a decision terminal under concurrent deciders", async () => {
    const clock = createTestClock();
    const harness = createPostgresHarness(fixture, clock);
    const created = await createRequest(harness);
    const deciders = [
      createPostgresHarness(fixture, clock),
      createPostgresHarness(fixture, clock),
      createPostgresHarness(fixture, clock),
    ];
    const responses = await Promise.all(
      deciders.map((decider) =>
        decider.handler(
          post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
            outcome: "approved",
            artifact: '{"grant":"race"}',
          }),
        ),
      ),
    );
    expect(responses.map((response) => response.status).sort()).toEqual([200, 409, 409]);
  });

  it("burns a code whose PKCE binding fails", async () => {
    const harness = createPostgresHarness(fixture);
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);

    await expectFailure(
      await harness.handler(
        post("/authorization/codes/consume", CLIENT_TOKEN, {
          code: decision.code,
          codeVerifier: `${CODE_VERIFIER.slice(0, 42)}Z`,
          redirectUri: REDIRECT_URI,
        }),
      ),
      "relay_code_invalid",
    );
    await expectFailure(await consume(harness, decision.code), "relay_code_already_consumed");
    await expectFailure(
      await claim(harness, decision.artifactId),
      "relay_artifact_already_claimed",
    );
  });

  it("refuses an expired code", async () => {
    const clock = createTestClock();
    const harness = createPostgresHarness(fixture, clock);
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);
    clock.advance(60_000);
    await expectFailure(await consume(harness, decision.code), "relay_expired");
    await harness.shutdown();
  });

  it("reports an unavailable database as 503 without a state change", async () => {
    const harness = createPostgresHarness(fixture);
    await harness.shutdown();
    await expectFailure(
      await harness.handler(post("/authorization/resume", CLIENT_TOKEN, { requestId: "any" })),
      "relay_store_unavailable",
    );
  });
});
