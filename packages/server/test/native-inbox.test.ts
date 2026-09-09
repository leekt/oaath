import { describe, expect, it } from "vitest";
import { createMemoryRelayStore, OaathRelayError } from "../src/index.js";
import { requestOwnerPhoneRevocation } from "../src/native.js";
import { createPostgresRelayStore } from "../src/postgres.js";
import {
  CLIENT_TOKEN,
  createHarness,
  createRequest,
  createTestClock,
  expectFailure,
  expectOk,
  get,
  OTHER_OWNER_TOKEN,
  OWNER_TOKEN,
  post,
} from "./support.js";
import { createPostgresFixture, requirePostgres } from "./support-postgres.js";
import { setupRevocation } from "./support-revocation.js";

type Inbox = {
  version: string;
  requests: { operationId: string; displayPayload: string; expiresAt: number }[];
};

describe("owner inbox from relay records", () => {
  it("lists only this owner's pending requests in bounded canonical order", async () => {
    const harness = createHarness();
    const ids: string[] = [];
    for (let i = 0; i < 22; i += 1) ids.push((await createRequest(harness)).requestId);
    ids.sort();
    const first = await expectOk<Inbox>(
      await harness.handler(get("/native/inbox", OWNER_TOKEN)),
      200,
    );
    expect(first.version).toBe("oaath.native-inbox/v1");
    expect(first.requests.map((entry) => entry.operationId)).toEqual(ids.slice(0, 20));
    for (const entry of first.requests) {
      expect(Object.keys(entry).sort()).toEqual(["displayPayload", "expiresAt", "operationId"]);
      const projection = await expectOk<Inbox["requests"][number]>(
        await harness.handler(get(`/native/projections/${entry.operationId}`, OWNER_TOKEN)),
        200,
      );
      expect(entry.displayPayload).toBe(projection.displayPayload);
      expect(entry.expiresAt).toBe(projection.expiresAt);
    }
    await expectFailure(
      await harness.handler(get("/native/inbox", CLIENT_TOKEN)),
      "relay_forbidden",
    );
    await expectFailure(await harness.handler(get("/native/inbox", null)), "relay_unauthenticated");
    const foreign = await expectOk<Inbox>(
      await harness.handler(get("/native/inbox", OTHER_OWNER_TOKEN)),
      200,
    );
    expect(foreign.requests).toEqual([]);
    expect(
      (
        await harness.handler(
          post(`/native/decisions/${ids[0]}`, OWNER_TOKEN, { command: "reject" }),
        )
      ).status,
    ).toBe(200);
    const after = await expectOk<Inbox>(
      await harness.handler(get("/native/inbox", OWNER_TOKEN)),
      200,
    );
    expect(after.requests.map((entry) => entry.operationId)).toEqual(ids.slice(1, 21));
    harness.clock.advance(300_000);
    const expired = await expectOk<Inbox>(
      await harness.handler(get("/native/inbox", OWNER_TOKEN)),
      200,
    );
    expect(expired.requests).toEqual([]);
    await harness.store.close();
  });

  it("combines pending revocations and permissions without reopening approval custody", async () => {
    const f = await setupRevocation(createMemoryRelayStore());
    try {
      const revocation = await requestOwnerPhoneRevocation(f.input);
      const { requestId: _id, ...scope } = f.signingRequest.permissionRequest;
      const permission = await createRequest(f.harness, JSON.stringify(scope));
      const inbox = await expectOk<Inbox>(
        await f.harness.handler(get("/native/inbox", OWNER_TOKEN)),
        200,
      );
      expect(inbox.requests.map((entry) => entry.operationId)).toEqual([
        revocation.operationId,
        permission.requestId,
      ]);
      const projection = await expectOk<Inbox["requests"][number]>(
        await f.harness.handler(get(`/native/projections/${revocation.operationId}`, OWNER_TOKEN)),
        200,
      );
      expect(inbox.requests[0]?.displayPayload).toBe(projection.displayPayload);
      expect(f.prepare).toHaveBeenCalledTimes(1);
      expect(
        (
          await f.harness.handler(
            post(`/native/revocation-decisions/${revocation.operationId}`, OWNER_TOKEN, {
              command: "reject",
            }),
          )
        ).status,
      ).toBe(200);
      const after = await expectOk<Inbox>(
        await f.harness.handler(get("/native/inbox", OWNER_TOKEN)),
        200,
      );
      expect(after.requests.map((entry) => entry.operationId)).toEqual([permission.requestId]);
    } finally {
      f.erase();
      await f.harness.store.close();
    }
  });

  it("does not turn an unreadable store into an empty inbox", async () => {
    const harness = createHarness(
      {},
      {
        ...createMemoryRelayStore(),
        async begin() {
          throw new OaathRelayError("relay_store_unavailable", "injected store failure");
        },
      },
    );
    await expectFailure(
      await harness.handler(get("/native/inbox", OWNER_TOKEN)),
      "relay_store_unavailable",
    );
  });
});

(requirePostgres ? describe : describe.skip)("PostgreSQL owner inbox", () => {
  it("recovers both kinds after full store/handler/pool recreation and sees an independent decision", async () => {
    const fixture = await createPostgresFixture();
    let first: Awaited<ReturnType<typeof setupRevocation>> | null = null;
    try {
      const firstPool = fixture.createPool();
      first = await setupRevocation(createPostgresRelayStore({ pool: firstPool }));
      const revocation = await requestOwnerPhoneRevocation(first.input);
      const { requestId: _id, ...scope } = first.signingRequest.permissionRequest;
      const permission = await createRequest(first.harness, JSON.stringify(scope));
      const foreign = createHarness(
        {
          ownerRouting: {
            async resolveOwner() {
              return { ownerDeviceId: "other-phone", ownerSubject: "subject-2" };
            },
          },
        },
        first.harness.store,
        first.harness.clock,
      );
      await createRequest(foreign);
      const before = await expectOk<Inbox>(
        await first.harness.handler(get("/native/inbox", OWNER_TOKEN)),
        200,
      );
      expect(before.requests.map((entry) => entry.operationId)).toEqual([
        revocation.operationId,
        permission.requestId,
      ]);
      const now = first.harness.clock.now();
      first.erase();
      await first.harness.store.close();
      first = null;
      await firstPool.end();

      const restored = createHarness(
        {
          kms: {
            async encrypt() {
              throw new Error("inbox must not encrypt");
            },
            async decrypt() {
              throw new Error("inbox must not decrypt");
            },
          },
        },
        createPostgresRelayStore({ pool: fixture.createPool() }),
        createTestClock(now),
      );
      const recovered = await expectOk<Inbox>(
        await restored.handler(get("/native/inbox", OWNER_TOKEN)),
        200,
      );
      expect(recovered).toEqual(before);
      const writer = createHarness(
        {},
        createPostgresRelayStore({ pool: fixture.createPool() }),
        createTestClock(now),
      );
      expect(
        (
          await writer.handler(
            post(`/native/decisions/${permission.requestId}`, OWNER_TOKEN, { command: "reject" }),
          )
        ).status,
      ).toBe(200);
      const after = await expectOk<Inbox>(
        await restored.handler(get("/native/inbox", OWNER_TOKEN)),
        200,
      );
      expect(after.requests.map((entry) => entry.operationId)).toEqual([revocation.operationId]);
      restored.clock.advance(60_000);
      const expired = await expectOk<Inbox>(
        await restored.handler(get("/native/inbox", OWNER_TOKEN)),
        200,
      );
      expect(expired.requests).toEqual([]);
    } finally {
      first?.erase();
      await fixture.end();
    }
  });
});
