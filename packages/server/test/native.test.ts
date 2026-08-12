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

import { readFileSync } from "node:fs";
import { hashOwnerSigningRequest } from "@oaath/protocol";
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
import { createKernelOwnerApprovalInput } from "./kernel-owner-signing-input.js";
import {
  APPROVABLE_PERMISSION_SCOPE,
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
const PERMISSION_SCOPE = APPROVABLE_PERMISSION_SCOPE;
const REQUEST_TTL_MS = 300_000;
const CODE_TTL_MS = 60_000;

/**
 * The ONE golden wire fixture shared with the strict Swift decoders
 * (`native/ios/Tests/OwnerPhoneTests/GoldenFixtureTests.swift` reads the same
 * file). Its exact owner-signing projection string is consumed as UTF-8 by both
 * languages; object entries cover the other union/decision variants.
 */
const GOLDEN = JSON.parse(
  readFileSync(new URL("./fixtures/owner-phone-golden.json", import.meta.url), "utf8"),
) as {
  readonly projection: Record<string, Record<string, unknown>>;
  readonly decision: Record<string, Record<string, unknown>>;
  readonly exactOwnerSigningProjectionBytes: string;
};

const GOLDEN_OWNER_SIGNING_SCOPE = GOLDEN.projection.ownerSigningRequest?.scope as {
  readonly requestHash: `0x${string}`;
  readonly request: Record<string, unknown>;
};
const GOLDEN_KERNEL_ENABLE_SCOPE = GOLDEN.projection.kernelEnableOwnerSigningRequest?.scope as {
  readonly requestHash: `0x${string}`;
  readonly request: Record<string, unknown>;
};
const GOLDEN_RAW_DIGEST_SCOPE = GOLDEN.projection.rawDigestOwnerSigningRequest?.scope as {
  readonly requestHash: `0x${string}`;
  readonly request: Record<string, unknown>;
};
/** Serialized exactly as a requesting client stores it into requestedScope. */
const OWNER_SIGNING_SCOPE = JSON.stringify(GOLDEN_OWNER_SIGNING_SCOPE.request);
const KERNEL_ENABLE_SCOPE = JSON.stringify(GOLDEN_KERNEL_ENABLE_SCOPE.request);
const RAW_DIGEST_REQUEST = GOLDEN_RAW_DIGEST_SCOPE.request;
const RAW_DIGEST_SCOPE = JSON.stringify(RAW_DIGEST_REQUEST);
const LEGACY_SIGNATURE_SCOPE = JSON.stringify({
  version: "oaath.signature-request/v1",
  kind: "signature-request",
  digest: `0x${"4b".repeat(32)}`,
  display: "{}",
});

const CLIENT: RelayCaller = Object.freeze({
  role: "client",
  clientId: "client-a",
  subject: "subject-1",
  redirectUris: Object.freeze([REDIRECT_URI]),
  organizationAudience: "org-1",
});
const OWNER: RelayCaller = Object.freeze({
  role: "owner",
  clientId: "owner-console",
  subject: "subject-1",
  redirectUris: Object.freeze([]),
  organizationAudience: null,
});
const OTHER_OWNER: RelayCaller = Object.freeze({ ...OWNER, subject: "subject-2" });

interface Fixture {
  readonly store: RelayStore;
  readonly clock: TestClock;
  readonly kms: RelayKms;
  readonly kmsEncryptions: () => number;
  readonly requestId: string;
}

async function fixture(requestedScope: string = PERMISSION_SCOPE): Promise<Fixture> {
  const store = createMemoryRelayStore();
  const clock = createTestClock();
  const baseKms = createTestKms();
  let encryptions = 0;
  const kms: RelayKms = {
    async encrypt(plaintext) {
      encryptions += 1;
      return baseKms.encrypt(plaintext);
    },
    decrypt: (ciphertextRef) => baseKms.decrypt(ciphertextRef),
  };
  const created = await createAuthorizationRequest({
    store,
    clock,
    caller: CLIENT,
    redirectUri: REDIRECT_URI,
    codeChallenge: await codeChallenge(),
    requestedScope,
    requestTtlMs: REQUEST_TTL_MS,
  });
  return { store, clock, kms, kmsEncryptions: () => encryptions, requestId: created.requestId };
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

    expect(OAATH_NATIVE_PROJECTION_VERSION).toBe("oaath.native-projection/v4");
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
      decision: "approve-or-reject",
      application: {
        applicationId: "oaath-native-tests",
        clientId: "client-a",
        origin: "https://app.example",
        deviceFingerprint: "8sWHndmh",
      },
      account: {
        accountIndex: "7",
        kernelVersion: "0.4.0",
        factoryRoute: "meta_factory",
        entryPointVersion: "0.7",
        ownerCredential: { kind: "ecdsa", address: `0x${"33".repeat(20)}` },
      },
      operatorCredential: { kind: "ecdsa", address: `0x${"44".repeat(20)}` },
      sessionSigner: null,
      chainScope: "all",
      calls: [
        {
          target: `0x${"11".repeat(20)}`,
          selector: "0x12345678",
          valueLimit: "100",
          argumentEquals: [],
        },
      ],
      requestedAt: 100,
      expiresAt: 200,
      policyValidAfter: 100,
      policyValidUntil: 190,
      perChainOperationLimit: 10,
    });
  });

  it("projects remote session custody as an approvable consent fact", async () => {
    // The custody model rides the same request hash the decision commits to,
    // so displaying it here is what makes approving it meaningful.
    const scope = JSON.parse(PERMISSION_SCOPE) as Record<string, unknown>;
    const fixed = await fixture(
      JSON.stringify({
        ...scope,
        sessionSigner: { mode: "oaath_hosted", providerId: "kms-primary" },
      }),
    );
    const projection = await project(fixed);
    expect(projection.scope).toMatchObject({
      kind: "permission-request",
      decision: "approve-or-reject",
      sessionSigner: { mode: "oaath_hosted", providerId: "kms-primary" },
    });
  });

  it.each([
    ["EIP-712", OWNER_SIGNING_SCOPE, GOLDEN_OWNER_SIGNING_SCOPE.request, "reject-only"],
    ["Kernel enable", KERNEL_ENABLE_SCOPE, GOLDEN_KERNEL_ENABLE_SCOPE.request, "approve-or-reject"],
    ["raw digest", RAW_DIGEST_SCOPE, RAW_DIGEST_REQUEST, "reject-only"],
  ])(
    "projects a complete %s owner-signing request and its exact hash",
    async (_, stored, request, decision) => {
      const fixed = await fixture(stored);
      const projection = await project(fixed);
      expect(projection.scope).toEqual({
        kind: "owner-signing-request",
        decision,
        requestHash: hashOwnerSigningRequest(request),
        request,
      });
    },
  );

  it("keeps non-P256 Kernel signer profiles reject-only", async () => {
    const original = GOLDEN_KERNEL_ENABLE_SCOPE.request as {
      signer: { ownerCredential: { version: string; publicKey: string } };
    };
    const credentials = [
      {
        version: original.signer.ownerCredential.version,
        kind: "ecdsa",
        address: `0x${"55".repeat(20)}`,
      },
      {
        version: original.signer.ownerCredential.version,
        kind: "webauthn",
        publicKey: original.signer.ownerCredential.publicKey,
        authenticatorIdHash: `0x${"44".repeat(32)}`,
      },
    ];

    for (const ownerCredential of credentials) {
      const request = structuredClone(GOLDEN_KERNEL_ENABLE_SCOPE.request) as {
        signer: { ownerCredential: unknown };
      };
      request.signer.ownerCredential = ownerCredential;
      const fixed = await fixture(JSON.stringify(request));
      expect((await project(fixed)).scope).toMatchObject({
        kind: "owner-signing-request",
        decision: "reject-only",
      });
    }
  });

  it("fails malformed and legacy signing scopes closed to labeled raw text", async () => {
    const wrongVersion = JSON.parse(OWNER_SIGNING_SCOPE) as Record<string, unknown>;
    wrongVersion.version = "oaath.owner-signing-request/v2";
    const extraField = JSON.parse(OWNER_SIGNING_SCOPE) as Record<string, unknown>;
    extraField.extra = true;
    const wrongDecision = { ...RAW_DIGEST_REQUEST, decision: "approve-or-reject" };
    for (const stored of [
      JSON.stringify(wrongVersion),
      JSON.stringify(extraField),
      JSON.stringify(wrongDecision),
      LEGACY_SIGNATURE_SCOPE,
    ]) {
      const fixed = await fixture(stored);
      const projection = await project(fixed);
      expect(projection.scope).toEqual({ kind: "raw", decision: "reject-only", text: stored });
    }
  });

  it("labels a non-protocol scope as raw text instead of dropping or failing", async () => {
    for (const stored of [RAW_SCOPE, "not json at all", "[1,2,3]", '"quoted"']) {
      const fixed = await fixture(stored);
      const projection = await project(fixed);
      expect(projection.scope).toEqual({ kind: "raw", decision: "reject-only", text: stored });
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
  it("verifies one Kernel artifact and replays without a second release", async () => {
    const input = createKernelOwnerApprovalInput();
    const fixed = await fixture(input.requestedScope);
    const projection = await project(fixed);
    expect(projection.scope).toMatchObject({
      kind: "owner-signing-request",
      decision: "approve-or-reject",
    });

    const decided = await submitOwnerPhoneDecision({
      store: fixed.store,
      clock: fixed.clock,
      kms: fixed.kms,
      caller: OWNER,
      operationId: fixed.requestId,
      command: { outcome: "approved", artifact: input.canonicalArtifact },
      codeTtlMs: CODE_TTL_MS,
    });
    expect(decided).toMatchObject({
      settlement: "decided",
      outcome: "approved",
    });
    expect(decided.release?.outcome).toBe("approved");
    expect(fixed.kmsEncryptions()).toBe(2);

    const replayed = await submitOwnerPhoneDecision({
      store: fixed.store,
      clock: fixed.clock,
      kms: fixed.kms,
      caller: OWNER,
      operationId: fixed.requestId,
      command: { outcome: "approved", artifact: "{}" },
      codeTtlMs: CODE_TTL_MS,
    });
    expect(replayed).toMatchObject({
      settlement: "replayed",
      outcome: "approved",
      release: null,
    });
    expect(fixed.kmsEncryptions()).toBe(2);
  });

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

  it.each([
    ["raw", RAW_SCOPE],
    ["EIP-712 owner signing", OWNER_SIGNING_SCOPE],
    ["raw-digest owner signing", RAW_DIGEST_SCOPE],
    ["legacy digest", LEGACY_SIGNATURE_SCOPE],
  ])(
    "refuses to approve a reject-only %s scope and still records its rejection",
    async (_label, requestedScope) => {
      const fixed = await fixture(requestedScope);
      await expectRelayFailure(() => decide(fixed, "approved"), "relay_request_invalid");
      expect(fixed.kmsEncryptions()).toBe(0);
      expect((await project(fixed)).scope).toMatchObject({ decision: "reject-only" });

      const rejected = await decide(fixed, "rejected");
      expect(rejected).toMatchObject({ settlement: "decided", outcome: "rejected" });
      expect(fixed.kmsEncryptions()).toBe(0);

      const replayed = await decide(fixed, "approved");
      expect(replayed).toMatchObject({ settlement: "replayed", outcome: "rejected" });
      expect(replayed.release).toBeNull();
      expect(fixed.kmsEncryptions()).toBe(0);
    },
  );

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
  it("serves every projection shape and pins shared owner-signing bytes", async () => {
    // The exact owner-signing bytes are shared with Swift. Other variants compare
    // closed decoded shapes after normalizing only the two store-random fields.
    const harness = createHarness();
    for (const [variant, requestedScope] of [
      ["permissionRequest", PERMISSION_SCOPE],
      ["ownerSigningRequest", OWNER_SIGNING_SCOPE],
      ["kernelEnableOwnerSigningRequest", KERNEL_ENABLE_SCOPE],
      ["rawDigestOwnerSigningRequest", RAW_DIGEST_SCOPE],
      ["raw", RAW_SCOPE],
    ] as const) {
      const golden = GOLDEN.projection[variant];
      if (!golden) throw new Error(`golden fixture is missing projection.${variant}`);
      const requestId = await createOverWire(harness, requestedScope);
      const response = await harness.handler(get(`/native/projections/${requestId}`, OWNER_TOKEN));
      expect(response.status).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      const body = JSON.parse(await response.text()) as Record<string, unknown>;
      expect(body.operationId).toBe(requestId);
      expect(body.operationId).toMatch(/^[A-Za-z0-9._~-]{1,64}$/u); // apns-collapse-id bound
      expect(body.displayPayload).toMatch(/^[A-Za-z0-9_-]{8}$/u);
      body.operationId = golden.operationId;
      body.displayPayload = golden.displayPayload;
      expect(body).toEqual(golden);
      if (variant === "ownerSigningRequest") {
        const exactBytes = new TextEncoder().encode(GOLDEN.exactOwnerSigningProjectionBytes);
        expect(new TextDecoder().decode(exactBytes)).toBe(JSON.stringify(body));
        expect(JSON.parse(new TextDecoder().decode(exactBytes))).toEqual(golden);
      }
    }
  });

  it("decides over the wire byte-for-byte from the shared golden fixture", async () => {
    const harness = createHarness();
    const requestId = await createOverWire(harness, PERMISSION_SCOPE);
    const decidedGolden = GOLDEN.decision.decidedApproved as Record<string, unknown> & {
      release: Record<string, unknown>;
    };

    const response = await harness.handler(
      post(`/native/decisions/${requestId}`, OWNER_TOKEN, {
        command: "approve",
        artifact: '{"grant":"approved"}',
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = JSON.parse(await response.text()) as Record<string, unknown>;
    expect(body.operationId).toBe(requestId);
    const release = body.release as Record<string, unknown>;
    expect(release.code).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(release.artifactId).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    body.operationId = decidedGolden.operationId;
    release.code = decidedGolden.release.code;
    release.artifactId = decidedGolden.release.artifactId;
    expect(body).toEqual(decidedGolden);

    // A replay answers the stored outcome — not the retried command — and
    // releases nothing: Decision.swift requires `release: null` on `replayed`.
    const replayed = JSON.parse(
      await (
        await harness.handler(
          post(`/native/decisions/${requestId}`, OWNER_TOKEN, { command: "reject" }),
        )
      ).text(),
    ) as Record<string, unknown>;
    expect(replayed.operationId).toBe(requestId);
    replayed.operationId = GOLDEN.decision.replayed?.operationId;
    expect(replayed).toEqual(GOLDEN.decision.replayed);

    // A rejected decision releases the exact rejected envelope.
    const rejectedId = await createOverWire(harness, RAW_SCOPE);
    const rejected = JSON.parse(
      await (
        await harness.handler(
          post(`/native/decisions/${rejectedId}`, OWNER_TOKEN, { command: "reject" }),
        )
      ).text(),
    ) as Record<string, unknown>;
    expect(rejected.operationId).toBe(rejectedId);
    rejected.operationId = GOLDEN.decision.decidedRejected?.operationId;
    expect(rejected).toEqual(GOLDEN.decision.decidedRejected);
  });

  it.each([
    ["raw", RAW_SCOPE],
    ["EIP-712 owner signing", OWNER_SIGNING_SCOPE],
    ["raw-digest owner signing", RAW_DIGEST_SCOPE],
    ["legacy digest", LEGACY_SIGNATURE_SCOPE],
  ])("keeps a %s scope reject-only over the native HTTP route", async (_label, requestedScope) => {
    const baseKms = createTestKms();
    let encryptions = 0;
    const harness = createHarness({
      kms: {
        async encrypt(plaintext) {
          encryptions += 1;
          return baseKms.encrypt(plaintext);
        },
        decrypt: (ciphertextRef) => baseKms.decrypt(ciphertextRef),
      },
    });
    const requestId = await createOverWire(harness, requestedScope);

    await expectFailure(
      await harness.handler(
        post(`/native/decisions/${requestId}`, OWNER_TOKEN, {
          command: "approve",
          artifact: "must-not-be-sealed",
        }),
      ),
      "relay_request_invalid",
    );
    expect(encryptions).toBe(0);

    const rejected = await expectOk<{ outcome: string; settlement: string }>(
      await harness.handler(
        post(`/native/decisions/${requestId}`, OWNER_TOKEN, { command: "reject" }),
      ),
      200,
    );
    expect(rejected).toMatchObject({ outcome: "rejected", settlement: "decided" });
    const replayed = await expectOk<{ outcome: string; settlement: string; release: unknown }>(
      await harness.handler(
        post(`/native/decisions/${requestId}`, OWNER_TOKEN, {
          command: "approve",
          artifact: "must-not-be-sealed",
        }),
      ),
      200,
    );
    expect(replayed).toMatchObject({ outcome: "rejected", settlement: "replayed", release: null });
    expect(encryptions).toBe(0);
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
      // The generic authorization route uses `{outcome}`; the native phone
      // route deliberately owns a different exact `{command}` envelope.
      { outcome: "approved", artifact: "x" },
      { outcome: "rejected" },
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
    expect(state.scope).toEqual({ kind: "raw", decision: "reject-only", text: RAW_SCOPE });
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
