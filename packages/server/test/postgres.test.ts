/**
 * PostgreSQL relay proof: row-locked one-time transitions under real
 * concurrency, on independent connections.
 *
 * Requires `OAATH_REQUIRE_POSTGRES=1`; skipped otherwise.
 *
 * @author taek <leekt216@gmail.com>
 */

import { hashGrantPolicy, hashGrantPolicyCalls, hashPermissionRequest } from "@oaath/protocol";
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
  LIVE_PERMISSION_POLICY,
  LIVE_PERMISSION_SCOPE,
  OWNER_TOKEN,
  post,
  REDIRECT_URI,
  TEST_CLOCK_SECONDS,
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
    const rows = await pool.query("SELECT schema_id, version FROM oaath_relay_schema_v4");
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

  it("verifies retained approved policy after claim and full instance recreation", async () => {
    const issuing = createPostgresHarness(fixture, createTestClock());
    const created = await createRequest(issuing, LIVE_PERMISSION_SCOPE);
    const approvedPolicy = {
      ...LIVE_PERMISSION_POLICY,
      calls: [{ ...LIVE_PERMISSION_POLICY.calls[0], valueLimit: "1" }],
      validUntil: TEST_CLOCK_SECONDS + 120,
    };
    const decision = await approve(
      issuing,
      created.requestId,
      JSON.stringify({
        version: "oaath.permission-decision/v1",
        kind: "approve",
        requestId: created.requestId,
        requestHash: hashPermissionRequest({
          ...JSON.parse(LIVE_PERMISSION_SCOPE),
          requestId: created.requestId,
        }),
        decidedAt: TEST_CLOCK_SECONDS,
        approvedPolicy,
        capabilityHash: `0x${"ab".repeat(32)}`,
      }),
    );
    await expectOk(await consume(issuing, decision.code), 200);
    await expectOk(await claim(issuing, decision.artifactId), 200);
    await issuing.shutdown();

    // New pool, store, handler, KMS and clock after code expiry. The retained
    // approval, rather than requestedScope or warm state, supplies the policy.
    const clock = createTestClock((TEST_CLOCK_SECONDS + 61) * 1_000);
    const verifier = createPostgresHarness(fixture, clock);
    const assertion = {
      grantId: created.requestId,
      revision: 1,
      subject: "subject-1",
      clientId: "client-a",
      organizationAudience: "org-1",
      requiredCallsDigest: hashGrantPolicyCalls(approvedPolicy.calls),
    };
    const result = await expectOk<{ state: string; ref?: { policyDigest: string } }>(
      await verifier.handler(post("/grants/verify", CLIENT_TOKEN, assertion)),
      200,
    );
    expect(result.state).toBe("authorized");
    expect(result.ref?.policyDigest).toBe(hashGrantPolicy(approvedPolicy));
    const broad = await expectOk<{ state: string; code: string }>(
      await verifier.handler(
        post("/grants/verify", CLIENT_TOKEN, {
          ...assertion,
          requiredCallsDigest: hashGrantPolicyCalls(LIVE_PERMISSION_POLICY.calls),
        }),
      ),
      200,
    );
    expect(broad).toEqual({ state: "denied", code: "grant_calls_mismatch" });
    await expectFailure(
      await claim(verifier, decision.artifactId),
      "relay_artifact_already_claimed",
    );
    clock.advance(60_000);
    expect(
      await expectOk(await verifier.handler(post("/grants/verify", CLIENT_TOKEN, assertion)), 200),
    ).toEqual({ state: "denied", code: "grant_expired" });
    await verifier.shutdown();
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
