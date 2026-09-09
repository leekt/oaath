import { p256 } from "@noble/curves/nist.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import {
  hashKernelV4RevocationSigningRequest,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createMemoryRelayStore } from "../src/index.js";
import { requestOwnerPhoneRevocation } from "../src/native.js";
import { createRelayHandler } from "../src/relay/handler.js";
import { createPostgresRelayStore } from "../src/store/postgres/store.js";
import {
  createTestAuthentication,
  createTestClock,
  createTestKms,
  expectFailure,
  expectOk,
  get,
  OTHER_OWNER_TOKEN,
  OWNER_TOKEN,
  post,
} from "./support.js";
import {
  createPostgresFixture,
  type PostgresFixture,
  requirePostgres,
} from "./support-postgres.js";

import { setupRevocation as setup } from "./support-revocation.js";

const projectionPath = (id: string) => `/native/projections/${id}`;
const decisionPath = (id: string) => `/native/revocation-decisions/${id}`;

describe("durable phone revocation admission and decision", () => {
  it("refuses a foreign member or unconfigured chain before preparation", async () => {
    const f = await setup(createMemoryRelayStore());
    for (const changed of [
      { caller: { ...f.input.caller, subject: "other" } },
      { caller: { ...f.input.caller, clientId: "other" } },
      { chainId: 1 },
    ]) {
      await expect(requestOwnerPhoneRevocation({ ...f.input, ...changed })).rejects.toMatchObject({
        code: "relay_forbidden",
      });
    }
    const snapshot = await f.input.directory.read();
    if (!snapshot) throw new Error("missing directory");
    await f.input.directory.replace({
      expectedRevision: snapshot.revision,
      directory: { ...snapshot.directory, memberships: [] },
    });
    await expect(requestOwnerPhoneRevocation(f.input)).rejects.toMatchObject({
      code: "relay_forbidden",
    });
    expect(f.prepare).not.toHaveBeenCalled();
    f.erase();
  });

  it("refuses a changed prepared permission and never stores it", async () => {
    const f = await setup(createMemoryRelayStore());
    const changed = {
      ...f.signingRequest,
      permissionRequest: { ...f.signingRequest.permissionRequest, requestId: "other" },
    };
    await expect(
      requestOwnerPhoneRevocation({ ...f.input, prepare: async () => changed }),
    ).rejects.toMatchObject({ code: "relay_request_invalid" });
    f.erase();
  });

  it("binds the phone and exact artifact; expired pending cannot decide", async () => {
    const f = await setup(createMemoryRelayStore());
    const queued = await requestOwnerPhoneRevocation(f.input);
    await expectFailure(
      await f.harness.handler(get(projectionPath(queued.operationId), OTHER_OWNER_TOKEN)),
      "relay_forbidden",
    );
    await expectFailure(
      await f.harness.handler(
        post(decisionPath(queued.operationId), OTHER_OWNER_TOKEN, { command: "reject" }),
      ),
      "relay_forbidden",
    );
    const encrypt = vi.spyOn(f.harness.kms, "encrypt");
    const wrongKey = p256.utils.randomPrivateKey();
    const wrongSignature = serializeOwnerSigningArtifact({
      version: "oaath.owner-signing-artifact/v1",
      kind: "p256",
      requestHash: hashKernelV4RevocationSigningRequest(f.signingRequest),
      signature: `0x${p256.sign(hexToBytes(f.signingRequest.expectedDigest.slice(2)), wrongKey, { prehash: false, lowS: true }).toCompactHex()}`,
    });
    wrongKey.fill(0);
    for (const artifact of [
      "invalid",
      wrongSignature,
      f.artifact({
        ...f.signingRequest,
        permissionRequest: { ...f.signingRequest.permissionRequest, requestId: "other" },
      }),
    ]) {
      await expectFailure(
        await f.harness.handler(
          post(decisionPath(queued.operationId), OWNER_TOKEN, { command: "approve", artifact }),
        ),
        "relay_request_invalid",
      );
    }
    expect(encrypt).not.toHaveBeenCalled();
    f.harness.clock.advance(60_001);
    await expectFailure(
      await f.harness.handler(
        post(decisionPath(queued.operationId), OWNER_TOKEN, { command: "reject" }),
      ),
      "relay_expired",
    );
    f.erase();
  });

  it("replays terminal evidence before expiry or new artifact processing, without OAuth release", async () => {
    const f = await setup(createMemoryRelayStore());
    // Expired execution policy does not prevent the owner revoking the permission.
    f.harness.clock.advance(100_000);
    const queued = await requestOwnerPhoneRevocation(f.input);
    const decided = await expectOk<Record<string, unknown>>(
      await f.harness.handler(
        post(decisionPath(queued.operationId), OWNER_TOKEN, {
          command: "approve",
          artifact: f.artifact(),
        }),
      ),
      200,
    );
    expect(decided).toEqual({
      version: "oaath.native-revocation-decision/v1",
      operationId: queued.operationId,
      outcome: "approved",
      decidedAt: f.harness.clock.now(),
      settlement: "decided",
    });
    f.harness.clock.advance(60_001);
    const encrypt = vi.spyOn(f.harness.kms, "encrypt");
    for (const command of [{ command: "reject" }, { command: "approve", artifact: "invalid" }]) {
      expect(
        await expectOk(
          await f.harness.handler(post(decisionPath(queued.operationId), OWNER_TOKEN, command)),
          200,
        ),
      ).toEqual({ ...decided, settlement: "replayed" });
    }
    expect(encrypt).not.toHaveBeenCalled();
    f.erase();
  });
});

(requirePostgres ? describe : describe.skip)(
  "phone revocation PostgreSQL restart and concurrent decisions",
  () => {
    let fixture: PostgresFixture;
    beforeAll(async () => {
      fixture = await createPostgresFixture();
    });
    afterAll(async () => {
      await fixture.end();
    });
    it("recreates pending state before signing and settles once on independent connections", async () => {
      const pool = fixture.createPool();
      const f = await setup(createPostgresRelayStore({ pool }));
      const queued = await requestOwnerPhoneRevocation(f.input);
      const raced = await requestOwnerPhoneRevocation(f.input);
      const before = await expectOk(
        await f.harness.handler(get(projectionPath(queued.operationId), OWNER_TOKEN)),
        200,
      );
      await f.harness.store.close();
      await pool.end();
      const fresh = (now = 160_000) => {
        const clock = createTestClock(now);
        const pool = fixture.createPool();
        const store = createPostgresRelayStore({ pool });
        const handler = createRelayHandler({
          store,
          clock,
          kms: createTestKms(),
          authentication: createTestAuthentication(),
          ownerRouting: {
            async resolveOwner() {
              throw new Error("revocation must not resolve authorization routing");
            },
          },
        });
        return { pool, store, handler };
      };
      const a = fresh();
      const b = fresh();
      expect(
        await expectOk(await a.handler(get(projectionPath(queued.operationId), OWNER_TOKEN)), 200),
      ).toEqual(before);
      const approved = await expectOk<Record<string, unknown>>(
        await a.handler(
          post(decisionPath(queued.operationId), OWNER_TOKEN, {
            command: "approve",
            artifact: f.artifact(),
          }),
        ),
        200,
      );
      expect(approved.outcome).toBe("approved");
      const custody = await a.store.begin();
      const retained = await custody.lockRevocationDecision(queued.operationId);
      expect(
        retained?.artifactRef !== null &&
          (await createTestKms().decrypt(retained?.artifactRef ?? "")) === f.artifact(),
      ).toBe(true);
      await custody.commit();
      const answers = await Promise.all([
        a.handler(
          post(decisionPath(raced.operationId), OWNER_TOKEN, {
            command: "approve",
            artifact: f.artifact(),
          }),
        ),
        b.handler(post(decisionPath(raced.operationId), OWNER_TOKEN, { command: "reject" })),
      ]);
      const outcomes = await Promise.all(
        answers.map((r) => expectOk<Record<string, unknown>>(r, 200)),
      );
      expect(outcomes[0]?.outcome).toBe(outcomes[1]?.outcome);
      expect(outcomes.map((r) => r.settlement).sort()).toEqual(["decided", "replayed"]);
      await a.pool.end();
      await b.pool.end();
      const c = fresh(260_000);
      expect(
        await expectOk(
          await c.handler(
            post(decisionPath(queued.operationId), OWNER_TOKEN, {
              command: "approve",
              artifact: "invalid",
            }),
          ),
          200,
        ),
      ).toEqual({ ...approved, settlement: "replayed" });
      await c.pool.end();
      f.erase();
    });
  },
);
