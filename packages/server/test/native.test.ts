/**
 * EXPERIMENTAL PREVIEW proofs for `@oaath/server/native`: the consent
 * projection's bounds and scope union, the decision saga's one-shot idempotency
 * and crash recovery, and the preview HTTP routes — including golden tests
 * pinning the response bytes to the exact key sets and value shapes the strict
 * Swift decoders (`native/ios/Sources/OwnerPhone/{Projection,Decision}.swift`)
 * accept. Swift cannot run under vitest, so the field lists are mirrored here;
 * a drifted envelope fails this file before it bricks the phone.
 *
 * @author taek <leekt216@gmail.com>
 */

import { describe, expect, it } from "vitest";
import { createAuthorizationRequest } from "../src/authorization/request.js";
import type { RelayClock } from "../src/clock.js";
import { submitOwnerPhoneDecision } from "../src/native/decision.js";
import {
  NATIVE_DISPLAY_PAYLOAD_LENGTH,
  OAATH_NATIVE_PROJECTION_VERSION,
  projectOwnerPhoneRequest,
} from "../src/native/projection.js";
import type { RelayCaller } from "../src/security/authentication.js";
import type { RelayKms } from "../src/security/kms.js";
import type { RelayStore } from "../src/store/interface.js";
import { withRelayTransaction } from "../src/store/interface.js";
import { createMemoryRelayStore } from "../src/store/memory.js";
import {
  CLIENT_TOKEN,
  codeChallenge,
  createHarness,
  createTestClock,
  createTestKms,
  expectFailure,
  expectOk,
  expectRelayFailure,
  get,
  type Harness,
  OWNER_TOKEN,
  post,
  REDIRECT_URI,
  type TestClock,
} from "./support.js";

/** An opaque scope string: projected as the labeled raw text, never dropped. */
const RAW_SCOPE = '{"permission":"erc20-transfer","token":"0xdeadbeefcafe","chainScope":"all"}';
/**
 * A real `@oaath/protocol` permission scope, exactly as `@oaath/sdk` serializes
 * it into `requestedScope` (a permission request without its `requestId`).
 */
const PERMISSION_SCOPE = JSON.stringify({
  version: "oaath.permission-request/v1",
  application: {
    applicationId: "oaath-native-tests",
    clientId: "client-a",
    origin: "https://app.example",
    deviceId: "device-1",
  },
  chainScope: "all",
  logicalAccount: {
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "7",
    kernelVersion: "0.4.0",
    factoryRoute: "meta_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"33".repeat(20)}`,
    },
  },
  operatorCredential: {
    version: "oaath.operator-credential-profile/v1",
    kind: "ecdsa",
    address: `0x${"44".repeat(20)}`,
  },
  policy: {
    version: "oaath.grant-policy/v1",
    calls: [
      {
        target: `0x${"11".repeat(20)}`,
        selector: "0x12345678",
        valueLimit: "100",
        argumentEquals: [],
      },
    ],
    validAfter: 100,
    validUntil: 190,
    perChainOperationLimit: 10,
  },
  requestedAt: 100,
  expiresAt: 200,
});
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

async function fixture(requestedScope: string = RAW_SCOPE): Promise<Fixture> {
  const store = createMemoryRelayStore();
  const clock = createTestClock();
  const created = await createAuthorizationRequest({
    store,
    clock,
    caller: CLIENT,
    redirectUri: REDIRECT_URI,
    codeChallenge: await codeChallenge(),
    requestedScope,
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
  it("is bounded, versioned, and stable for the bound owner", async () => {
    const fixed = await fixture();
    const projection = await project(fixed);

    expect(projection.version).toBe(OAATH_NATIVE_PROJECTION_VERSION);
    expect(projection.operationId).toBe(fixed.requestId);
    expect(projection.displayPayload).toHaveLength(NATIVE_DISPLAY_PAYLOAD_LENGTH);
    expect(projection.displayPayload).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(projection.expiresAt).toBe(fixed.clock.now() + REQUEST_TTL_MS);
    expect(projection.client).toEqual({ clientId: CLIENT.clientId, redirectUri: REDIRECT_URI });
    // The exact envelope the Swift decoder pins; nothing else may ride along.
    expect(Object.keys(projection).sort()).toEqual([
      "client",
      "displayPayload",
      "expiresAt",
      "operationId",
      "scope",
      "version",
    ]);

    const again = await project(fixed);
    expect(again).toEqual(projection);
  });

  it("projects the full consent facts of a protocol permission scope", async () => {
    const fixed = await fixture(PERMISSION_SCOPE);
    const projection = await project(fixed);

    expect(projection.scope).toEqual({
      kind: "permission-request",
      chainScope: "all",
      calls: [{ target: `0x${"11".repeat(20)}`, selector: "0x12345678", valueLimit: "100" }],
      expiresAt: 200,
      perChainOperationLimit: 10,
    });
  });

  it("labels a non-protocol scope as raw text instead of dropping or failing", async () => {
    for (const stored of [RAW_SCOPE, "not json at all", "[1,2,3]", '"quoted"']) {
      const fixed = await fixture(stored);
      const projection = await project(fixed);
      expect(projection.scope).toEqual({ kind: "raw", text: stored });
    }
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

/** Creates a request over the wire with a chosen scope; returns its id. */
async function createOverWire(harness: Harness, requestedScope: string): Promise<string> {
  const created = await expectOk<{ requestId: string }>(
    await harness.handler(
      post("/authorization/requests", CLIENT_TOKEN, {
        redirectUri: REDIRECT_URI,
        codeChallenge: await codeChallenge(),
        requestedScope,
      }),
    ),
    201,
  );
  return created.requestId;
}

describe("experimental owner-phone preview routes", () => {
  it("serves the projection with the exact envelope Projection.swift decodes", async () => {
    const harness = createHarness();
    const requestId = await createOverWire(harness, PERMISSION_SCOPE);

    const response = await harness.handler(get(`/native/projections/${requestId}`, OWNER_TOKEN));
    // Golden: decode the actual response bytes and pin every closed key set and
    // value shape the strict Swift decoder (`Projection.swift`) accepts.
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = JSON.parse(await response.text()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "client",
      "displayPayload",
      "expiresAt",
      "operationId",
      "scope",
      "version",
    ]);
    expect(body.version).toBe("oaath.native-projection/v1");
    expect(body.operationId).toBe(requestId);
    expect(body.operationId).toMatch(/^[A-Za-z0-9._~-]{1,64}$/u); // apns-collapse-id bound
    expect(body.displayPayload).toMatch(/^[A-Za-z0-9_-]{8}$/u);
    expect(Number.isSafeInteger(body.expiresAt)).toBe(true);
    const client = body.client as Record<string, unknown>;
    expect(Object.keys(client).sort()).toEqual(["clientId", "redirectUri"]);
    expect(client).toEqual({ clientId: "client-a", redirectUri: REDIRECT_URI });
    const scope = body.scope as Record<string, unknown>;
    expect(Object.keys(scope).sort()).toEqual([
      "calls",
      "chainScope",
      "expiresAt",
      "kind",
      "perChainOperationLimit",
    ]);
    expect(scope.kind).toBe("permission-request");
    expect(scope.chainScope).toBe("all");
    expect(Number.isSafeInteger(scope.expiresAt)).toBe(true);
    expect(Number.isSafeInteger(scope.perChainOperationLimit)).toBe(true);
    const calls = scope.calls as Record<string, unknown>[];
    expect(calls).toHaveLength(1);
    for (const call of calls) {
      expect(Object.keys(call).sort()).toEqual(["selector", "target", "valueLimit"]);
      expect(call.target).toMatch(/^0x[0-9a-f]{40}$/u);
      expect(call.selector).toMatch(/^0x[0-9a-f]{8}$/u);
      expect(call.valueLimit).toMatch(/^(?:0|[1-9][0-9]*)$/u);
    }
  });

  it("serves a raw scope as the labeled union branch Projection.swift decodes", async () => {
    const harness = createHarness();
    const requestId = await createOverWire(harness, RAW_SCOPE);
    const body = await expectOk<{ scope: Record<string, unknown> }>(
      await harness.handler(get(`/native/projections/${requestId}`, OWNER_TOKEN)),
      200,
    );
    expect(Object.keys(body.scope).sort()).toEqual(["kind", "text"]);
    expect(body.scope).toEqual({ kind: "raw", text: RAW_SCOPE });
  });

  it("decides over the wire with the exact envelope Decision.swift decodes", async () => {
    const harness = createHarness();
    const requestId = await createOverWire(harness, RAW_SCOPE);

    const response = await harness.handler(
      post(`/native/decisions/${requestId}`, OWNER_TOKEN, {
        command: "approve",
        artifact: '{"grant":"approved"}',
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = JSON.parse(await response.text()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual([
      "decidedAt",
      "operationId",
      "outcome",
      "release",
      "settlement",
    ]);
    expect(body.operationId).toBe(requestId);
    expect(body.outcome).toBe("approved");
    expect(body.settlement).toBe("decided");
    expect(Number.isSafeInteger(body.decidedAt)).toBe(true);
    const release = body.release as Record<string, unknown>;
    // Decision.swift: `decided` must carry a release agreeing with the outcome.
    expect(Object.keys(release).sort()).toEqual([
      "artifactId",
      "code",
      "codeExpiresAt",
      "decidedAt",
      "outcome",
      "redirectUri",
    ]);
    expect(release.outcome).toBe("approved");
    expect(release.decidedAt).toBe(body.decidedAt);
    expect(release.code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(release.artifactId).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(release.redirectUri).toBe(REDIRECT_URI);

    // A replay answers the stored outcome — not the retried command — and
    // releases nothing: Decision.swift requires `release: null` on `replayed`.
    const replayed = JSON.parse(
      await (
        await harness.handler(
          post(`/native/decisions/${requestId}`, OWNER_TOKEN, { command: "reject" }),
        )
      ).text(),
    ) as Record<string, unknown>;
    expect(Object.keys(replayed).sort()).toEqual([
      "decidedAt",
      "operationId",
      "outcome",
      "release",
      "settlement",
    ]);
    expect(replayed).toMatchObject({
      operationId: requestId,
      outcome: "approved",
      settlement: "replayed",
      decidedAt: body.decidedAt,
    });
    expect(replayed.release).toBeNull();
  });

  it("serves a rejected release with the exact keys Decision.swift decodes", async () => {
    const harness = createHarness();
    const requestId = await createOverWire(harness, RAW_SCOPE);
    const body = await expectOk<{ release: Record<string, unknown> }>(
      await harness.handler(
        post(`/native/decisions/${requestId}`, OWNER_TOKEN, { command: "reject" }),
      ),
      200,
    );
    expect(Object.keys(body.release).sort()).toEqual(["decidedAt", "outcome"]);
    expect(body.release.outcome).toBe("rejected");
  });

  it("enforces the owner role on both preview routes", async () => {
    const harness = createHarness();
    const requestId = await createOverWire(harness, RAW_SCOPE);
    await expectFailure(
      await harness.handler(get(`/native/projections/${requestId}`, CLIENT_TOKEN)),
      "relay_forbidden",
    );
    await expectFailure(
      await harness.handler(
        post(`/native/decisions/${requestId}`, CLIENT_TOKEN, { command: "reject" }),
      ),
      "relay_forbidden",
    );
    await expectFailure(
      await harness.handler(get(`/native/projections/${requestId}`, null)),
      "relay_unauthenticated",
    );
  });

  it("rejects a malformed decision command over the wire", async () => {
    const harness = createHarness();
    const requestId = await createOverWire(harness, RAW_SCOPE);
    for (const body of [
      { command: "maybe" },
      { command: "approve" },
      { command: "reject", artifact: "x" },
      { command: "approve", artifact: "x", extra: 1 },
      {},
    ]) {
      await expectFailure(
        await harness.handler(post(`/native/decisions/${requestId}`, OWNER_TOKEN, body)),
        "relay_request_invalid",
      );
    }
    // The request is still undecided: a refused envelope decides nothing.
    const state = await expectOk<{ scope: unknown }>(
      await harness.handler(get(`/native/projections/${requestId}`, OWNER_TOKEN)),
      200,
    );
    expect(state.scope).toEqual({ kind: "raw", text: RAW_SCOPE });
  });

  it("keeps the preview namespace closed: unknown routes and wrong methods", async () => {
    const harness = createHarness();
    await expectFailure(await harness.handler(get("/native", OWNER_TOKEN)), "relay_not_found");
    await expectFailure(
      await harness.handler(get("/native/projections", OWNER_TOKEN)),
      "relay_not_found",
    );
    await expectFailure(
      await harness.handler(get("/native/projections/a/b", OWNER_TOKEN)),
      "relay_not_found",
    );
    await expectFailure(
      await harness.handler(post("/native/devices", OWNER_TOKEN, { deviceToken: "ab" })),
      "relay_not_found",
    );
    await expectFailure(
      await harness.handler(post("/native/projections/some-id", OWNER_TOKEN, {})),
      "relay_method_not_allowed",
    );
    await expectFailure(
      await harness.handler(get("/native/decisions/some-id", OWNER_TOKEN)),
      "relay_method_not_allowed",
    );
    await expectFailure(
      await harness.handler(get("/native/projections/unknown-id", OWNER_TOKEN)),
      "relay_not_found",
    );
    await expectFailure(
      await harness.handler(get("/native/projections/not%20canonical", OWNER_TOKEN)),
      "relay_request_invalid",
    );
  });
});
