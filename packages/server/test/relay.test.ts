/**
 * Relay handler round-trips and wire failure projection.
 *
 * @author taek <leekt216@gmail.com>
 */

import { describe, expect, it } from "vitest";
import { OaathRelayError, type RelayErrorCode } from "../src/relay/errors.js";
import { createRelayHandler, type RelayHandlerOptions } from "../src/relay/handler.js";
import type { RelayStore, RelayTransaction } from "../src/store/interface.js";
import { createMemoryRelayStore } from "../src/store/memory.js";
import {
  approve,
  CLIENT_TOKEN,
  claim,
  codeChallenge,
  consume,
  createHarness,
  createRequest,
  createTestAuthentication,
  createTestClock,
  createTestKms,
  expectFailure,
  expectOk,
  get,
  ORIGIN,
  OTHER_CLIENT_TOKEN,
  OWNER_TOKEN,
  post,
  REDIRECT_URI,
} from "./support.js";

function expectConstructionFailure(build: () => unknown, code: RelayErrorCode): void {
  try {
    build();
  } catch (error) {
    expect(error).toBeInstanceOf(OaathRelayError);
    if (error instanceof OaathRelayError) expect(error.code).toBe(code);
    return;
  }
  throw new Error("expected a relay construction failure");
}

describe("relay handler", () => {
  it("round-trips create, fetch, approve, consume, and claim", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    expect(created.requestId).toMatch(/^[A-Za-z0-9_-]{43}$/u);

    const state = await expectOk<{
      requestId: string;
      clientId: string;
      redirectUri: string;
      requestedScope: string;
      expired: boolean;
      decision: unknown;
    }>(
      await harness.handler(get(`/authorization/requests/${created.requestId}`, OWNER_TOKEN)),
      200,
    );
    expect(state).toMatchObject({
      requestId: created.requestId,
      clientId: "client-a",
      redirectUri: REDIRECT_URI,
      requestedScope: '{"chainScope":"all"}',
      expired: false,
      decision: null,
    });

    const decision = await approve(harness, created.requestId);
    expect(decision.redirectUri).toBe(REDIRECT_URI);
    expect(decision.code).toMatch(/^[A-Za-z0-9_-]{43}$/u);

    const consumed = await expectOk<{ requestId: string; artifactId: string }>(
      await consume(harness, decision.code),
      200,
    );
    expect(consumed).toEqual({
      requestId: created.requestId,
      artifactId: decision.artifactId,
    });

    const claimed = await expectOk<{ requestId: string; artifact: string }>(
      await claim(harness, decision.artifactId),
      200,
    );
    expect(claimed).toEqual({
      requestId: created.requestId,
      artifact: '{"grant":"approved"}',
    });
  });

  it("reports a rejected decision through fetch and resume", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const rejected = await expectOk<{ outcome: string; decidedAt: number }>(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
          outcome: "rejected",
        }),
      ),
      200,
    );
    expect(rejected.outcome).toBe("rejected");

    const resumed = await expectOk<{ decision: { outcome: string; decidedAt: number } }>(
      await harness.handler(
        post("/authorization/resume", CLIENT_TOKEN, { requestId: created.requestId }),
      ),
      200,
    );
    expect(resumed.decision).toEqual({ outcome: "rejected", decidedAt: rejected.decidedAt });
  });

  it("never returns a body field other than the error code", async () => {
    const harness = createHarness();
    const response = await harness.handler(get("/authorization/requests/unknown-id", OWNER_TOKEN));
    expect(response.status).toBe(404);
    const body = (await response.json()) as { error: Record<string, unknown> };
    expect(Object.keys(body)).toEqual(["error"]);
    expect(Object.keys(body.error)).toEqual(["code"]);
  });

  describe("routing", () => {
    it("rejects an unknown route", async () => {
      const harness = createHarness();
      await expectFailure(await harness.handler(get("/", OWNER_TOKEN)), "relay_not_found");
      await expectFailure(
        await harness.handler(get("/authorization", OWNER_TOKEN)),
        "relay_not_found",
      );
      await expectFailure(
        await harness.handler(get("/authorization/requests/a/b/c", OWNER_TOKEN)),
        "relay_not_found",
      );
      await expectFailure(
        await harness.handler(post("/authorization/codes/other", CLIENT_TOKEN, {})),
        "relay_not_found",
      );
      await expectFailure(
        await harness.handler(post("/authorization/artifacts/a/burn", CLIENT_TOKEN)),
        "relay_not_found",
      );
      await expectFailure(
        await harness.handler(post("/authorization/requests/a/approve", OWNER_TOKEN, {})),
        "relay_not_found",
      );
    });

    it("rejects a wrong method", async () => {
      const harness = createHarness();
      await expectFailure(
        await harness.handler(get("/authorization/requests", CLIENT_TOKEN)),
        "relay_method_not_allowed",
      );
      await expectFailure(
        await harness.handler(post("/authorization/requests/some-id", OWNER_TOKEN, {})),
        "relay_method_not_allowed",
      );
      await expectFailure(
        await harness.handler(get("/authorization/resume", CLIENT_TOKEN)),
        "relay_method_not_allowed",
      );
      await expectFailure(
        await harness.handler(get("/authorization/codes/consume", CLIENT_TOKEN)),
        "relay_method_not_allowed",
      );
      await expectFailure(
        await harness.handler(get("/authorization/artifacts/some-id/claim", CLIENT_TOKEN)),
        "relay_method_not_allowed",
      );
      await expectFailure(
        await harness.handler(get("/authorization/requests/some-id/decision", OWNER_TOKEN)),
        "relay_method_not_allowed",
      );
    });

    it("rejects a non-canonical path identifier", async () => {
      const harness = createHarness();
      await expectFailure(
        await harness.handler(get("/authorization/requests/not%20canonical", OWNER_TOKEN)),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post("/authorization/artifacts/not!canonical/claim", CLIENT_TOKEN)),
        "relay_request_invalid",
      );
    });
  });

  describe("authentication", () => {
    it("rejects a missing or unknown credential", async () => {
      const harness = createHarness();
      await expectFailure(
        await harness.handler(post("/authorization/requests", null, {})),
        "relay_unauthenticated",
      );
      await expectFailure(
        await harness.handler(post("/authorization/requests", "unknown-token", {})),
        "relay_unauthenticated",
      );
    });

    it("rejects an authentication port that throws", async () => {
      const harness = createHarness({
        authentication: {
          async authenticate() {
            throw new Error("backend down");
          },
        },
      });
      await expectFailure(
        await harness.handler(post("/authorization/requests", CLIENT_TOKEN, {})),
        "relay_unauthenticated",
      );
    });

    it("rejects a caller in the wrong role", async () => {
      const harness = createHarness();
      await expectFailure(
        await harness.handler(post("/authorization/requests", OWNER_TOKEN, {})),
        "relay_forbidden",
      );
      await expectFailure(
        await harness.handler(get("/authorization/requests/some-id", CLIENT_TOKEN)),
        "relay_forbidden",
      );
    });

    it("rejects an authentication port that breaks its contract", async () => {
      for (const authenticated of [
        { role: "admin", clientId: "c", subject: "s", redirectUris: [] },
        { role: "client", clientId: "c", subject: "s" },
        { role: "client", clientId: "", subject: "s", redirectUris: [] },
        { role: "client", clientId: "c", subject: "s", redirectUris: "https://a" },
        { role: "client", clientId: "c", subject: "s", redirectUris: [1] },
        {
          role: "client",
          clientId: "c",
          subject: "s",
          redirectUris: Array.from({ length: 9 }, (_, index) => `https://a/${index}`),
        },
      ]) {
        const harness = createHarness({
          authentication: {
            async authenticate() {
              return authenticated;
            },
          },
        });
        await expectFailure(
          await harness.handler(post("/authorization/requests", CLIENT_TOKEN, {})),
          "relay_internal",
        );
      }
    });
  });

  describe("wire capture", () => {
    it("rejects a body that is not exact JSON", async () => {
      const harness = createHarness();
      const path = "/authorization/requests";
      const challenge = await codeChallenge();
      const valid = {
        redirectUri: REDIRECT_URI,
        codeChallenge: challenge,
        requestedScope: "{}",
      };

      await expectFailure(
        await harness.handler(
          new Request(`${ORIGIN}${path}`, {
            method: "POST",
            headers: { authorization: `Bearer ${CLIENT_TOKEN}` },
            body: "{}",
          }),
        ),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(
          new Request(`${ORIGIN}${path}`, {
            method: "POST",
            headers: {
              authorization: `Bearer ${CLIENT_TOKEN}`,
              "content-type": "application/json",
            },
            body: "{not json",
          }),
        ),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, CLIENT_TOKEN, [valid])),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, CLIENT_TOKEN, { ...valid, extra: 1 })),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, CLIENT_TOKEN, { redirectUri: REDIRECT_URI })),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, CLIENT_TOKEN, { ...valid, requestedScope: "" })),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, CLIENT_TOKEN, { ...valid, requestedScope: "a\u0000b" })),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, CLIENT_TOKEN, { ...valid, codeChallenge: "short" })),
        "relay_request_invalid",
      );
    });

    it("rejects a body beyond its bound", async () => {
      const harness = createHarness({ maxBodyBytes: 256 });
      await expectFailure(
        await harness.handler(
          post("/authorization/requests", CLIENT_TOKEN, {
            redirectUri: REDIRECT_URI,
            codeChallenge: await codeChallenge(),
            requestedScope: "x".repeat(512),
          }),
        ),
        "relay_request_invalid",
      );
    });

    it("rejects an unsupported decision outcome or shape", async () => {
      const harness = createHarness();
      const created = await createRequest(harness);
      const path = `/authorization/requests/${created.requestId}/decision`;
      await expectFailure(
        await harness.handler(post(path, OWNER_TOKEN, { outcome: "maybe" })),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, OWNER_TOKEN, { outcome: "approved" })),
        "relay_request_invalid",
      );
      await expectFailure(
        await harness.handler(post(path, OWNER_TOKEN, { outcome: "rejected", artifact: "x" })),
        "relay_request_invalid",
      );
    });

    it("refuses a decision body that names a subject or client", async () => {
      const harness = createHarness();
      const created = await createRequest(harness);
      const path = `/authorization/requests/${created.requestId}/decision`;
      // A named subject is not a bound subject: the stored request owns it.
      for (const body of [
        { outcome: "rejected", subjectId: "subject-1" },
        { outcome: "rejected", subject: "subject-2" },
        { outcome: "approved", artifact: "x", subjectId: "subject-2" },
        { outcome: "approved", artifact: "x", clientId: "client-a" },
      ]) {
        await expectFailure(
          await harness.handler(post(path, OWNER_TOKEN, body)),
          "relay_request_invalid",
        );
      }
      // The request is still undecided: a rejected envelope decides nothing.
      const state = await expectOk<{ decision: unknown }>(
        await harness.handler(get(`/authorization/requests/${created.requestId}`, OWNER_TOKEN)),
        200,
      );
      expect(state.decision).toBeNull();
    });

    it("rejects a redirect URI the deployment did not register", async () => {
      const harness = createHarness();
      await expectFailure(
        await harness.handler(
          post("/authorization/requests", CLIENT_TOKEN, {
            redirectUri: "https://attacker.example/callback",
            codeChallenge: await codeChallenge(),
            requestedScope: "{}",
          }),
        ),
        "relay_forbidden",
      );
    });
  });

  describe("injected ports", () => {
    it("projects a limiter verdict to 429", async () => {
      const harness = createHarness({
        rateLimit: {
          async check(input) {
            expect(input).toEqual({ route: "authorization.create", clientId: "client-a" });
            return "limited";
          },
        },
      });
      await expectFailure(
        await harness.handler(post("/authorization/requests", CLIENT_TOKEN, {})),
        "relay_rate_limited",
      );
    });

    it("treats an unreadable limiter as limited", async () => {
      const harness = createHarness({
        rateLimit: {
          async check() {
            throw new Error("limiter down");
          },
        },
      });
      await expectFailure(
        await harness.handler(post("/authorization/requests", CLIENT_TOKEN, {})),
        "relay_rate_limited",
      );
    });

    it("allows a limiter that permits the call", async () => {
      const harness = createHarness({
        rateLimit: {
          async check() {
            return "allowed";
          },
        },
      });
      await createRequest(harness);
    });

    it("projects an unavailable store to 503", async () => {
      const store = createMemoryRelayStore();
      const harness = createHarness({}, store);
      await store.close();
      await expectFailure(
        await harness.handler(
          post("/authorization/requests", CLIENT_TOKEN, {
            redirectUri: REDIRECT_URI,
            codeChallenge: await codeChallenge(),
            requestedScope: "{}",
          }),
        ),
        "relay_store_unavailable",
      );
    });

    it("projects an unproven commit to 500 without retrying", async () => {
      const inner = createMemoryRelayStore();
      let commits = 0;
      const ambiguous: RelayStore = {
        async begin(): Promise<RelayTransaction> {
          const transaction = await inner.begin();
          return {
            ...transaction,
            async commit() {
              commits += 1;
              await transaction.rollback();
              throw new OaathRelayError("relay_state_ambiguous", "commit is unproven");
            },
          };
        },
        close: () => inner.close(),
      };
      const harness = createHarness({}, ambiguous);
      await expectFailure(
        await harness.handler(
          post("/authorization/requests", CLIENT_TOKEN, {
            redirectUri: REDIRECT_URI,
            codeChallenge: await codeChallenge(),
            requestedScope: "{}",
          }),
        ),
        "relay_state_ambiguous",
      );
      expect(commits).toBe(1);
    });

    it("projects an unavailable KMS to 503", async () => {
      const harness = createHarness({
        kms: {
          async encrypt() {
            throw new Error("kms down");
          },
          async decrypt() {
            throw new Error("kms down");
          },
        },
      });
      const created = await createRequest(harness);
      await expectFailure(
        await harness.handler(
          post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
            outcome: "approved",
            artifact: "secret",
          }),
        ),
        "relay_kms_unavailable",
      );
    });

    it("rejects a KMS reference that leaks plaintext", async () => {
      const harness = createHarness({
        kms: {
          async encrypt(plaintext: string) {
            return `ref:${plaintext}`;
          },
          async decrypt(reference: string) {
            return reference;
          },
        },
      });
      const created = await createRequest(harness);
      await expectFailure(
        await harness.handler(
          post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
            outcome: "approved",
            artifact: "secret",
          }),
        ),
        "relay_kms_unavailable",
      );
    });

    it("rejects handler options that break their contract", () => {
      const complete: RelayHandlerOptions = {
        store: createMemoryRelayStore(),
        authentication: createTestAuthentication(),
        kms: createTestKms(),
        clock: createTestClock(),
      };
      for (const options of [
        undefined,
        null,
        [complete],
        {},
        { ...complete, store: {} },
        { ...complete, authentication: {} },
        { ...complete, kms: { encrypt: 1, decrypt: 1 } },
        { ...complete, clock: { now: "later" } },
        { ...complete, rateLimit: {} },
        { ...complete, extra: 1 },
        { ...complete, requestTtlMs: 0 },
        { ...complete, requestTtlMs: 86_400_001 },
        // A code may never outlive the RFC 6749 ten-minute ceiling.
        { ...complete, codeTtlMs: 600_001 },
        { ...complete, maxBodyBytes: -1 },
      ]) {
        expectConstructionFailure(
          () => createRelayHandler(options as unknown as RelayHandlerOptions),
          "relay_internal",
        );
      }
      expect(() => createRelayHandler(complete)).not.toThrow();
    });

    it("rejects an unreadable injected clock", async () => {
      const harness = createHarness({
        clock: {
          now() {
            throw new Error("no clock");
          },
        },
      });
      await expectFailure(
        await harness.handler(
          post("/authorization/requests", CLIENT_TOKEN, {
            redirectUri: REDIRECT_URI,
            codeChallenge: await codeChallenge(),
            requestedScope: "{}",
          }),
        ),
        "relay_internal",
      );
    });
  });

  it("keeps one client's authorization invisible to another", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    await expectFailure(
      await harness.handler(
        post("/authorization/resume", OTHER_CLIENT_TOKEN, { requestId: created.requestId }),
      ),
      "relay_not_found",
    );
  });
});

describe("URL-only service surface", () => {
  const ACCOUNT_PROFILE = Object.freeze({
    version: "oaath.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: "0",
    kernelVersion: "0.4.0",
    factoryRoute: "kernel_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: `0x${"11".repeat(20)}`,
    },
  });

  function chainPort(overrides: Record<string, unknown> = {}) {
    return {
      chainId: 31_337,
      reads: async (request: unknown) => ({ echoed: "reads", request }),
      observation: async () => undefined,
      bundler: async () => ({ accepting: true }),
      quote: async () => ({ nonceKey: "0" }),
      submission: async () => ({ userOperationHash: `0x${"aa".repeat(32)}` }),
      usage: async () => ({ status: "complete" }),
      feePayer: null,
      ...overrides,
    };
  }

  function bootstrapOptions(overrides: Record<string, unknown> = {}) {
    return {
      bootstrap: {
        application: {
          applicationId: "app-a",
          applicationName: "OAAth Example",
          clientId: "client-a",
          redirectUris: [REDIRECT_URI],
        },
        userHandle: "user-1",
        account: ACCOUNT_PROFILE,
        ownerValidator: `0x${"22".repeat(20)}`,
      },
      chains: [chainPort()],
      ...overrides,
    } as Partial<RelayHandlerOptions>;
  }

  it("serves the exact versioned bootstrap document to a client", async () => {
    const harness = createHarness(bootstrapOptions());
    const document = await expectOk<Record<string, unknown>>(
      await harness.handler(get("/bootstrap", CLIENT_TOKEN)),
      200,
    );
    expect(document).toMatchObject({
      version: "oaath.service-bootstrap/v1",
      userHandle: "user-1",
      chains: [{ chainId: 31_337, usage: true, feePayer: null }],
    });
    await expectFailure(await harness.handler(get("/bootstrap", OWNER_TOKEN)), "relay_forbidden");
    await expectFailure(await harness.handler(get("/bootstrap", null)), "relay_unauthenticated");
  });

  it("serves no bootstrap unless the deployment configured one", async () => {
    const harness = createHarness();
    await expectFailure(await harness.handler(get("/bootstrap", CLIENT_TOKEN)), "relay_not_found");
  });

  it("refuses to construct on a malformed bootstrap or bootstrap without chains", async () => {
    expectConstructionFailure(
      () => createHarness(bootstrapOptions({ chains: undefined })),
      "relay_internal",
    );
    expectConstructionFailure(
      () =>
        createHarness(
          bootstrapOptions({
            bootstrap: { application: {}, userHandle: "", account: {}, ownerValidator: null },
          }),
        ),
      "relay_internal",
    );
  });

  it("relays each chain port and reports absence explicitly", async () => {
    const harness = createHarness(bootstrapOptions());
    const reads = await expectOk<Record<string, unknown>>(
      await harness.handler(post("/chains/31337/reads", CLIENT_TOKEN, { request: { a: 1 } })),
      200,
    );
    expect(reads).toEqual({ present: true, result: { echoed: "reads", request: { a: 1 } } });
    // JSON cannot carry undefined; the envelope states presence explicitly.
    const observation = await expectOk<Record<string, unknown>>(
      await harness.handler(post("/chains/31337/observation", CLIENT_TOKEN, { request: {} })),
      200,
    );
    expect(observation).toEqual({ present: false, result: null });
    const submission = await expectOk<Record<string, unknown>>(
      await harness.handler(post("/chains/31337/submissions", CLIENT_TOKEN, { request: {} })),
      200,
    );
    expect(submission).toEqual({
      present: true,
      result: { userOperationHash: `0x${"aa".repeat(32)}` },
    });
  });

  it("fails closed on unknown chains, ports, callers, and throwing ports", async () => {
    const throwing = chainPort({
      quote: async () => {
        throw new Error("boom");
      },
      usage: null,
    });
    const harness = createHarness(bootstrapOptions({ chains: [throwing] }));
    await expectFailure(
      await harness.handler(post("/chains/1/reads", CLIENT_TOKEN, { request: {} })),
      "relay_not_found",
    );
    await expectFailure(
      await harness.handler(post("/chains/31337/paymaster", CLIENT_TOKEN, { request: {} })),
      "relay_not_found",
    );
    // A chain that serves no usage evidence has no usage route at all.
    await expectFailure(
      await harness.handler(post("/chains/31337/usage", CLIENT_TOKEN, { request: {} })),
      "relay_not_found",
    );
    await expectFailure(
      await harness.handler(post("/chains/31337/reads", OWNER_TOKEN, { request: {} })),
      "relay_forbidden",
    );
    await expectFailure(
      await harness.handler(post("/chains/31337/quote", CLIENT_TOKEN, { request: {} })),
      "relay_chain_unavailable",
    );
    await expectFailure(
      await harness.handler(post("/chains/31337/reads", CLIENT_TOKEN, { extra: 1 })),
      "relay_request_invalid",
    );
  });

  it("records invalidations durably and enforces them on the chain routes", async () => {
    const harness = createHarness(bootstrapOptions());
    const capabilityHash = `0x${"ab".repeat(32)}`;
    const submission = { request: { prepared: { grantId: "grant-1" } } };

    // Before invalidation the ports serve the Grant.
    await expectOk(
      await harness.handler(post("/chains/31337/submissions", CLIENT_TOKEN, submission)),
      200,
    );

    // Recording is durable and idempotent: a replay answers the stored record,
    // so one Grant has exactly one invalidation time and one evidence hash.
    const first = await expectOk<Record<string, unknown>>(
      await harness.handler(
        post("/invalidations", CLIENT_TOKEN, { grantId: "grant-1", capabilityHash }),
      ),
      200,
    );
    expect(first.evidenceHash).toMatch(/^0x[0-9a-f]{64}$/u);
    harness.clock.advance(5_000);
    const replay = await expectOk<Record<string, unknown>>(
      await harness.handler(
        post("/invalidations", CLIENT_TOKEN, { grantId: "grant-1", capabilityHash }),
      ),
      200,
    );
    expect(replay).toEqual(first);

    // Another client reads absence, never existence.
    await expectFailure(
      await harness.handler(
        post("/invalidations", OTHER_CLIENT_TOKEN, { grantId: "grant-1", capabilityHash }),
      ),
      "relay_not_found",
    );

    // Enforcement: the routes whose requests act for the Grant refuse it.
    await expectFailure(
      await harness.handler(post("/chains/31337/submissions", CLIENT_TOKEN, submission)),
      "relay_capability_invalidated",
    );
    await expectFailure(
      await harness.handler(
        post("/chains/31337/usage", CLIENT_TOKEN, {
          request: { grantId: "grant-1", chainId: 31_337 },
        }),
      ),
      "relay_capability_invalidated",
    );
    // Chain reads grant nothing and keep serving.
    await expectOk(
      await harness.handler(post("/chains/31337/reads", CLIENT_TOKEN, { request: {} })),
      200,
    );
    // A different Grant is untouched.
    await expectOk(
      await harness.handler(
        post("/chains/31337/submissions", CLIENT_TOKEN, {
          request: { prepared: { grantId: "grant-2" } },
        }),
      ),
      200,
    );
  });

  it("releases the decided code to exactly the creating client", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);

    // Undecided: pending, and only for the creating client.
    expect(
      await expectOk(
        await harness.handler(
          get(`/authorization/requests/${created.requestId}/code`, CLIENT_TOKEN),
        ),
        200,
      ),
    ).toEqual({ outcome: "pending" });
    await expectFailure(
      await harness.handler(
        get(`/authorization/requests/${created.requestId}/code`, OTHER_CLIENT_TOKEN),
      ),
      "relay_not_found",
    );

    // Approved: the picked-up code is byte-identical to the released one and
    // pickup is idempotent — consumption stays one-shot elsewhere.
    const approved = await approve(harness, created.requestId);
    const picked = await expectOk<Record<string, unknown>>(
      await harness.handler(get(`/authorization/requests/${created.requestId}/code`, CLIENT_TOKEN)),
      200,
    );
    expect(picked).toEqual({
      outcome: "approved",
      decidedAt: approved.decidedAt,
      code: approved.code,
      codeExpiresAt: approved.codeExpiresAt,
    });
    const again = await expectOk<Record<string, unknown>>(
      await harness.handler(get(`/authorization/requests/${created.requestId}/code`, CLIENT_TOKEN)),
      200,
    );
    expect(again).toEqual(picked);

    // Past the code expiry the pickup is gone, like the code itself.
    harness.clock.advance(120_000);
    await expectFailure(
      await harness.handler(get(`/authorization/requests/${created.requestId}/code`, CLIENT_TOKEN)),
      "relay_expired",
    );
  });

  it("reports a rejection through pickup without a code", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    await harness.handler(
      post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
        outcome: "rejected",
      }),
    );
    const picked = await expectOk<Record<string, unknown>>(
      await harness.handler(get(`/authorization/requests/${created.requestId}/code`, CLIENT_TOKEN)),
      200,
    );
    expect(picked).toMatchObject({ outcome: "rejected" });
  });
});
