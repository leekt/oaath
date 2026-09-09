import { p256 } from "@noble/curves/nist.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import {
  hashKernelV4RevocationSigningRequest,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createMemoryRelayStore, OaathRelayError, type RelayStore } from "../src/index.js";
import { requestOwnerPhoneRevocation } from "../src/native.js";
import { createRelayHandler } from "../src/relay/handler.js";
import { createPostgresRelayStore } from "../src/store/postgres/store.js";
import {
  CLIENT_TOKEN,
  createTestAuthentication,
  createTestClock,
  createTestKms,
  expectFailure,
  expectOk,
  get,
  OTHER_CLIENT_TOKEN,
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
  it("recovers the same pending request before preparing or opening its retained approval again", async () => {
    const f = await setup(createMemoryRelayStore());
    const first = await requestOwnerPhoneRevocation(f.input);
    const decrypt = vi.spyOn(f.input.kms, "decrypt");
    const second = await requestOwnerPhoneRevocation(f.input);
    expect(second.operationId).toBe(first.operationId);
    expect(second.expiresAt).toBe(first.expiresAt);
    expect(f.prepare).toHaveBeenCalledTimes(1);
    expect(decrypt).not.toHaveBeenCalled();
    f.erase();
  });

  it("serves authenticated request/status metadata and replaces only expired undecided custody", async () => {
    const f = await setup(createMemoryRelayStore());
    const handler = createRelayHandler({
      store: f.input.store,
      kms: f.input.kms,
      clock: f.input.clock,
      authentication: createTestAuthentication(),
      ownerRouting: f.input.directory,
      requestTtlMs: 60_000,
      revocations: { directory: f.input.directory, prepare: f.prepare },
    });
    const path = `/grants/${f.input.grantId}/revocations/${f.input.chainId}`;
    await expectFailure(await handler(get(path, OTHER_CLIENT_TOKEN)), "relay_forbidden");
    await expectFailure(await handler(get(path, CLIENT_TOKEN)), "relay_not_found");
    await expectFailure(await handler(post(path, OWNER_TOKEN, {})), "relay_forbidden");
    await expectFailure(
      await handler(post(path, CLIENT_TOKEN, { account: "untrusted" })),
      "relay_request_invalid",
    );
    expect(f.prepare).not.toHaveBeenCalled();
    const first = await expectOk<Record<string, unknown>>(
      await handler(post(path, CLIENT_TOKEN, {})),
      201,
    );
    expect(first).toMatchObject({
      grantId: f.input.grantId,
      chainId: f.input.chainId,
      status: "pending",
    });
    expect(Object.keys(first).sort()).toEqual([
      "chainId",
      "expiresAt",
      "grantId",
      "operationId",
      "status",
    ]);
    expect(await expectOk(await handler(post(path, CLIENT_TOKEN, {})), 200)).toEqual(first);
    f.harness.clock.advance(60_001);
    expect(await expectOk(await handler(get(path, CLIENT_TOKEN)), 200)).toMatchObject({
      status: "expired",
    });
    const replacement = await expectOk<Record<string, unknown>>(
      await handler(post(path, CLIENT_TOKEN, {})),
      201,
    );
    expect(replacement.operationId).not.toBe(first.operationId);
    await expectFailure(
      await handler(
        post(decisionPath(String(first.operationId)), OWNER_TOKEN, { command: "reject" }),
      ),
      "relay_expired",
    );
    await expectOk(
      await handler(
        post(decisionPath(String(replacement.operationId)), OWNER_TOKEN, {
          command: "approve",
          artifact: f.artifact(),
        }),
      ),
      200,
    );
    f.harness.clock.advance(60_001);
    const approved = await expectOk<Record<string, unknown>>(
      await handler(post(path, CLIENT_TOKEN, {})),
      200,
    );
    expect(approved).toMatchObject({ operationId: replacement.operationId, status: "approved" });
    expect(f.prepare).toHaveBeenCalledTimes(2);
    f.erase();
  });

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
    it("shares one admitted request across concurrent workers and recovers a lost commit response", async () => {
      const a = fixture.createPool();
      const b = fixture.createPool();
      const storeA = createPostgresRelayStore({ pool: a });
      const storeB = createPostgresRelayStore({ pool: b });
      const f = await setup(storeA);
      let prepared = 0;
      let release!: () => void;
      const bothPrepared = new Promise<void>((resolve) => {
        release = resolve;
      });
      const prepare = async () => {
        prepared += 1;
        if (prepared === 2) release();
        await bothPrepared;
        return f.signingRequest;
      };
      const answers = await Promise.all(
        [storeA, storeB].map((store) =>
          requestOwnerPhoneRevocation({ ...f.input, store, prepare }),
        ),
      );
      expect(answers[0]?.operationId).toBe(answers[1]?.operationId);
      expect(answers.map((answer) => answer.created).sort()).toEqual([false, true]);
      expect(prepared).toBe(2); // Preparation reserves nothing; only the stored winner reaches the phone.

      const lost = await setup(storeA);
      const uncertain: RelayStore = {
        close: async () => {},
        async begin() {
          const transaction = await storeA.begin();
          let inserted = false;
          return {
            ...transaction,
            async insertRevocationRequest(record) {
              inserted = await transaction.insertRevocationRequest(record);
              return inserted;
            },
            async commit() {
              await transaction.commit();
              if (inserted)
                throw new OaathRelayError("relay_state_ambiguous", "commit response lost");
            },
          };
        },
      };
      await expect(
        requestOwnerPhoneRevocation({ ...lost.input, store: uncertain }),
      ).rejects.toMatchObject({ code: "relay_state_ambiguous" });
      expect(lost.prepare).toHaveBeenCalledTimes(1);
      await storeA.close();
      await storeB.close();
      await a.end();
      await b.end();
      const c = fixture.createPool();
      const recovered = createPostgresRelayStore({ pool: c });
      const noEffect = async () => {
        throw new Error("recovery must not prepare or open KMS");
      };
      const status = await requestOwnerPhoneRevocation({
        ...lost.input,
        store: recovered,
        clock: createTestClock(160_000),
        kms: { encrypt: noEffect, decrypt: noEffect },
        directory: { resolveRevocationOwner: noEffect },
        prepare: noEffect,
      });
      expect(status).toMatchObject({
        created: false,
        status: "pending",
        grantId: lost.input.grantId,
        chainId: 31337,
      });
      const handler = createRelayHandler({
        store: recovered,
        clock: createTestClock(160_000),
        kms: { encrypt: noEffect, decrypt: noEffect },
        authentication: createTestAuthentication(),
        ownerRouting: { resolveOwner: noEffect },
      });
      expect(
        await expectOk(
          await handler(get(`/grants/${lost.input.grantId}/revocations/31337`, CLIENT_TOKEN)),
          200,
        ),
      ).toMatchObject({ operationId: status.operationId, status: "pending" });
      await recovered.close();
      await c.end();
      f.erase();
      lost.erase();
    });

    it("recreates pending state before signing and settles once on independent connections", async () => {
      const pool = fixture.createPool();
      const f = await setup(createPostgresRelayStore({ pool }));
      const queued = await requestOwnerPhoneRevocation(f.input);
      const race = await setup(f.input.store);
      const raced = await requestOwnerPhoneRevocation(race.input);
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
            artifact: race.artifact(),
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
      race.erase();
    });
  },
);
