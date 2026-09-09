/**
 * Process-restart proof: every in-memory instance (pool, store, handler) is
 * recreated, and the durable relay state alone decides what may still happen.
 *
 * Requires `OAATH_REQUIRE_POSTGRES=1`; skipped otherwise.
 *
 * @author taek <leekt216@gmail.com>
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { withRelayTransaction } from "../src/store/interface.js";
import {
  approve,
  claim,
  consume,
  createRequest,
  createTestClock,
  expectFailure,
  expectOk,
  get,
  OTHER_OWNER_TOKEN,
  OWNER_TOKEN,
  permissionArtifact,
  post,
} from "./support.js";
import {
  createPostgresFixture,
  createPostgresHarness,
  type PostgresFixture,
  requirePostgres,
} from "./support-postgres.js";

(requirePostgres ? describe : describe.skip)("relay restart", () => {
  let fixture: PostgresFixture;

  beforeAll(async () => {
    fixture = await createPostgresFixture();
  });

  afterAll(async () => {
    await fixture.end();
  });

  it("keeps the distinct approving device after a full restart and routing change", async () => {
    const clock = createTestClock();
    const before = createPostgresHarness(fixture, clock, {
      async resolveOwner() {
        return { ownerDeviceId: "team-phone", ownerSubject: "subject-2" };
      },
    });
    const created = await createRequest(before);
    await before.shutdown();

    const after = createPostgresHarness(fixture, clock);
    const stored = await withRelayTransaction(after.store, (transaction) =>
      transaction.lockAuthorizationRequest(created.requestId),
    );
    expect(stored).toMatchObject({
      subject: "subject-1",
      ownerDeviceId: "team-phone",
      ownerSubject: "subject-2",
    });
    await expectFailure(
      await after.handler(get(`/authorization/requests/${created.requestId}`, OWNER_TOKEN)),
      "relay_not_found",
    );
    const state = await expectOk<{ requestId: string; decision: unknown }>(
      await after.handler(get(`/authorization/requests/${created.requestId}`, OTHER_OWNER_TOKEN)),
      200,
    );
    expect(state).toMatchObject({ requestId: created.requestId, decision: null });

    const decision = await expectOk<{ code: string }>(
      await after.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OTHER_OWNER_TOKEN, {
          outcome: "approved",
          artifact: permissionArtifact(created.requestId),
        }),
      ),
      200,
    );
    await expectOk(await consume(after, decision.code), 200);
    await after.shutdown();
  });

  it("keeps a code and an artifact one-shot across a restart", async () => {
    const clock = createTestClock();
    const before = createPostgresHarness(fixture, clock);
    const created = await createRequest(before);
    const decision = await approve(before, created.requestId);
    await expectOk(await consume(before, decision.code), 200);
    await before.shutdown();

    const after = createPostgresHarness(fixture, clock);
    // The consume already happened; the restart may not undo or repeat it.
    await expectFailure(await consume(after, decision.code), "relay_code_already_consumed");

    const claimed = await expectOk<{ artifact: string }>(
      await claim(after, decision.artifactId),
      200,
    );
    expect(claimed.artifact === permissionArtifact(created.requestId)).toBe(true);
    await after.shutdown();

    const last = createPostgresHarness(fixture, clock);
    await expectFailure(await claim(last, decision.artifactId), "relay_artifact_already_claimed");
    await last.shutdown();
  });

  it("keeps a decision terminal across a restart", async () => {
    const clock = createTestClock();
    const before = createPostgresHarness(fixture, clock);
    const created = await createRequest(before);
    await approve(before, created.requestId);
    await before.shutdown();

    const after = createPostgresHarness(fixture, clock);
    await expectFailure(
      await after.handler(
        new Request(`https://relay.example/authorization/requests/${created.requestId}/decision`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${OWNER_TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ outcome: "rejected" }),
        }),
      ),
      "relay_already_decided",
    );
    await after.shutdown();
  });
});
