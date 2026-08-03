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
