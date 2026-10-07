import { describe, expect, it } from "vitest";
import {
  approve,
  CLIENT_TOKEN,
  claim,
  consume,
  createHarness,
  createRequest,
  createTestAuthentication,
  expectFailure,
  expectOk,
  get,
  OWNER_TOKEN,
  permissionArtifact,
  post,
} from "./support.js";
import {
  createPostgresFixture,
  createPostgresHarness,
  requirePostgres,
} from "./support-postgres.js";

const withdraw = (
  harness: Pick<ReturnType<typeof createHarness>, "handler">,
  requestId: string,
  token = CLIENT_TOKEN,
) => harness.handler(post(`/authorization/requests/${requestId}/withdraw`, token, {}));

describe("creator withdrawal", () => {
  it("withdraws only pending requests and prevents a later approval or code release", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    await expectFailure(await withdraw(harness, created.requestId, OWNER_TOKEN), "relay_forbidden");
    const result = await expectOk<{ outcome: string }>(
      await withdraw(harness, created.requestId),
      200,
    );
    expect(result.outcome).toBe("withdrawn");
    await expectFailure(
      await harness.handler(
        post(`/native/decisions/${created.requestId}`, OWNER_TOKEN, { command: "reject" }),
      ),
      "relay_already_decided",
    );
    expect(await expectOk(await withdraw(harness, created.requestId), 200)).toEqual(result);
    await expectFailure(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
          outcome: "approved",
          artifact: permissionArtifact(created.requestId),
        }),
      ),
      "relay_already_decided",
    );
    expect(
      await expectOk(
        await harness.handler(
          get(`/authorization/requests/${created.requestId}/code`, CLIENT_TOKEN),
        ),
        200,
      ),
    ).toMatchObject({ outcome: "withdrawn" });
  });
  it("binds withdrawal, resume and pickup to the creating subject as well as client", async () => {
    const creator = createHarness();
    const request = await createRequest(creator);
    const authentication = createTestAuthentication();
    const foreign = createHarness(
      {
        authentication: {
          async authenticate(input) {
            const caller = await authentication.authenticate(input);
            return caller && typeof caller === "object"
              ? { ...caller, subject: "foreign-subject" }
              : caller;
          },
        },
      },
      creator.store,
      creator.clock,
    );
    await expectFailure(await withdraw(foreign, request.requestId), "relay_not_found");
    await expectFailure(
      await foreign.handler(
        post("/authorization/resume", CLIENT_TOKEN, { requestId: request.requestId }),
      ),
      "relay_not_found",
    );
    await expectFailure(
      await foreign.handler(get(`/authorization/requests/${request.requestId}/code`, CLIENT_TOKEN)),
      "relay_not_found",
    );
  });

  it("reports an existing approval without revoking it or consuming its code", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const approved = await approve(harness, created.requestId);
    expect(await expectOk(await withdraw(harness, created.requestId), 200)).toMatchObject({
      outcome: "approved",
    });
    await expectOk(await consume(harness, approved.code), 200);
    await expectOk(await claim(harness, approved.artifactId), 200);
  });
  it("reports expiry without deciding the request", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    harness.clock.advance(100_000_000);
    expect(await expectOk(await withdraw(harness, created.requestId), 200)).toMatchObject({
      outcome: "expired",
    });
  });
});

(requirePostgres ? describe : describe.skip)("PostgreSQL withdrawal race", () => {
  it("retains exactly one winner across independent connections and recreation", async () => {
    const fixture = await createPostgresFixture();
    try {
      const first = createPostgresHarness(fixture);
      const second = createPostgresHarness(fixture);
      const created = await createRequest(first);
      const [withdrawn, decided] = await Promise.all([
        withdraw(first, created.requestId),
        second.handler(
          post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
            outcome: "approved",
            artifact: permissionArtifact(created.requestId),
          }),
        ),
      ]);
      const outcome = (await expectOk<{ outcome: string }>(withdrawn, 200)).outcome;
      expect(["withdrawn", "approved"]).toContain(outcome);
      expect(decided.status).toBe(outcome === "approved" ? 200 : 409);
      await first.shutdown();
      await second.shutdown();
      const recreated = createPostgresHarness(fixture);
      expect(await expectOk(await withdraw(recreated, created.requestId), 200)).toMatchObject({
        outcome,
      });
      await recreated.shutdown();
    } finally {
      await fixture.end();
    }
  });
});
