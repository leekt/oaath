/**
 * EXPERIMENTAL PREVIEW proofs for `@oaath/server/native`: projection bounds and
 * opacity, and the decision saga's one-shot idempotency and crash recovery.
 *
 * @author taek <leekt216@gmail.com>
 */

import { describe, expect, it } from "vitest";
import { createAuthorizationRequest } from "../src/authorization/request.js";
import type { RelayClock } from "../src/clock.js";
import { submitOwnerPhoneDecision } from "../src/native/decision.js";
import {
  NATIVE_DISPLAY_PAYLOAD_LENGTH,
  projectOwnerPhoneRequest,
} from "../src/native/projection.js";
import type { RelayCaller } from "../src/security/authentication.js";
import type { RelayKms } from "../src/security/kms.js";
import type { RelayStore } from "../src/store/interface.js";
import { withRelayTransaction } from "../src/store/interface.js";
import { createMemoryRelayStore } from "../src/store/memory.js";
import {
  codeChallenge,
  createTestClock,
  createTestKms,
  expectRelayFailure,
  REDIRECT_URI,
  type TestClock,
} from "./support.js";

/** Distinctive permission text: no projection or payload may ever contain it. */
const SCOPE = '{"permission":"erc20-transfer","token":"0xdeadbeefcafe","chainScope":"all"}';
const REQUEST_TTL_MS = 300_000;
const CODE_TTL_MS = 60_000;

const CLIENT: RelayCaller = Object.freeze({
  role: "client",
  clientId: "client-a",
  subject: "subject-1",
  redirectUris: Object.freeze([REDIRECT_URI]),
});
const OWNER: RelayCaller = Object.freeze({
  role: "owner",
  clientId: "owner-console",
  subject: "subject-1",
  redirectUris: Object.freeze([]),
});
const OTHER_OWNER: RelayCaller = Object.freeze({ ...OWNER, subject: "subject-2" });

interface Fixture {
  readonly store: RelayStore;
  readonly clock: TestClock;
  readonly kms: RelayKms;
  readonly requestId: string;
}

async function fixture(): Promise<Fixture> {
  const store = createMemoryRelayStore();
  const clock = createTestClock();
  const created = await createAuthorizationRequest({
    store,
    clock,
    caller: CLIENT,
    redirectUri: REDIRECT_URI,
    codeChallenge: await codeChallenge(),
    requestedScope: SCOPE,
    requestTtlMs: REQUEST_TTL_MS,
  });
  return { store, clock, kms: createTestKms(), requestId: created.requestId };
}

function project(
  fixed: Fixture,
  caller: RelayCaller = OWNER,
  requestId: string = fixed.requestId,
): ReturnType<typeof projectOwnerPhoneRequest> {
  return projectOwnerPhoneRequest({ store: fixed.store, clock: fixed.clock, caller, requestId });
}

function decide(
  fixed: Fixture,
  outcome: "approved" | "rejected",
  caller: RelayCaller = OWNER,
  clock: RelayClock = fixed.clock,
): ReturnType<typeof submitOwnerPhoneDecision> {
  return submitOwnerPhoneDecision({
    store: fixed.store,
    clock,
    kms: fixed.kms,
    caller,
    operationId: fixed.requestId,
    command:
      outcome === "approved"
        ? { outcome: "approved", artifact: '{"grant":"approved"}' }
        : { outcome: "rejected" },
    codeTtlMs: CODE_TTL_MS,
  });
}

describe("experimental owner-phone projection", () => {
  it("is bounded, opaque, and stable for the bound owner", async () => {
    const fixed = await fixture();
    const projection = await project(fixed);

    expect(projection.operationId).toBe(fixed.requestId);
    expect(projection.displayPayload).toHaveLength(NATIVE_DISPLAY_PAYLOAD_LENGTH);
    expect(projection.displayPayload).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(projection.expiresAt).toBe(fixed.clock.now() + REQUEST_TTL_MS);
    // Exactly three fields: nothing else may ride along toward Apple.
    expect(Object.keys(projection).sort()).toEqual(["displayPayload", "expiresAt", "operationId"]);

    const again = await project(fixed);
    expect(again).toEqual(projection);
  });

  it("leaks no permission detail into the projection", async () => {
    const fixed = await fixture();
    const projection = await project(fixed);
    const serialized = JSON.stringify(projection);

    for (const secret of ["erc20-transfer", "0xdeadbeefcafe", "chainScope", REDIRECT_URI]) {
      expect(serialized).not.toContain(secret);
    }
    expect(serialized).not.toContain(CLIENT.clientId);
    expect(serialized).not.toContain(OWNER.subject);
  });

  it("binds the projection to the request's own subject", async () => {
    const fixed = await fixture();
    const mine = await project(fixed);
    const other = await fixture();
    // Same subject, different request: a different match code.
    expect((await project(other)).displayPayload).not.toBe(mine.displayPayload);

    await expectRelayFailure(() => project(fixed, OTHER_OWNER), "relay_not_found");
    await expectRelayFailure(() => project(fixed, CLIENT), "relay_forbidden");
    await expectRelayFailure(() => project(fixed, OWNER, "unknown-request"), "relay_not_found");
  });

  it("refuses to project an expired or decided request", async () => {
    const expired = await fixture();
    expired.clock.advance(REQUEST_TTL_MS);
    await expectRelayFailure(() => project(expired), "relay_expired");

    const decided = await fixture();
    await decide(decided, "rejected");
    await expectRelayFailure(() => project(decided), "relay_already_decided");
  });
});

describe("experimental owner-phone decision saga", () => {
  it("decides once and releases the one-time material to that call only", async () => {
    const fixed = await fixture();
    const decided = await decide(fixed, "approved");

    expect(decided.settlement).toBe("decided");
    expect(decided.outcome).toBe("approved");
    expect(decided.operationId).toBe(fixed.requestId);
    expect(decided.release?.outcome).toBe("approved");
    if (decided.release?.outcome === "approved") {
      expect(decided.release.code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    }

    const replayed = await decide(fixed, "approved");
    expect(replayed.settlement).toBe("replayed");
    expect(replayed.outcome).toBe("approved");
    expect(replayed.decidedAt).toBe(decided.decidedAt);
    expect(replayed.release).toBeNull();
  });

  it("answers the stored outcome, not the resubmitted command", async () => {
    const fixed = await fixture();
    const rejected = await decide(fixed, "rejected");
    expect(rejected).toMatchObject({ settlement: "decided", outcome: "rejected" });
    expect(rejected.release?.outcome).toBe("rejected");

    const contradicted = await decide(fixed, "approved");
    expect(contradicted).toMatchObject({ settlement: "replayed", outcome: "rejected" });
    expect(contradicted.decidedAt).toBe(rejected.decidedAt);
  });

  it("recovers a durable outcome the phone never saw", async () => {
    const fixed = await fixture();
    const decided = await decide(fixed, "approved");

    // The saga holds no in-process state, so a retry after a crash reads the
    // durable decision record the transaction committed before responding.
    const stored = await withRelayTransaction(fixed.store, (transaction) =>
      transaction.lockAuthorizationDecision(fixed.requestId),
    );
    expect(stored).toMatchObject({ outcome: "approved", decidedAt: decided.decidedAt });

    // A later retry, on a clock that moved past the request's expiry, still
    // answers the stored outcome instead of failing expired.
    const later = createTestClock(fixed.clock.now() + REQUEST_TTL_MS * 2);
    const replayed = await decide(fixed, "approved", OWNER, later);
    expect(replayed).toMatchObject({ settlement: "replayed", outcome: "approved" });
    expect(replayed.decidedAt).toBe(decided.decidedAt);
  });

  it("never decides for the wrong caller, an unknown operation, or after expiry", async () => {
    const fixed = await fixture();
    await expectRelayFailure(() => decide(fixed, "approved", CLIENT), "relay_forbidden");
    await expectRelayFailure(() => decide(fixed, "approved", OTHER_OWNER), "relay_not_found");

    const expired = await fixture();
    expired.clock.advance(REQUEST_TTL_MS);
    await expectRelayFailure(() => decide(expired, "approved"), "relay_expired");
  });
});
