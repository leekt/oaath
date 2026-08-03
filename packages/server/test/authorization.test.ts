/**
 * Authorization lifecycle: every terminal transition happens once and every
 * ambiguous or hostile path fails closed.
 *
 * @author taek <leekt216@gmail.com>
 */

import { describe, expect, it } from "vitest";
import { verifyPkceS256 } from "../src/authorization/challenge.js";
import {
  approve,
  CLIENT_TOKEN,
  CODE_VERIFIER,
  claim,
  codeChallenge,
  consume,
  createHarness,
  createRequest,
  expectFailure,
  expectOk,
  get,
  OTHER_CLIENT_TOKEN,
  OTHER_OWNER_TOKEN,
  OWNER_TOKEN,
  post,
  REDIRECT_URI,
} from "./support.js";

describe("PKCE S256 verification", () => {
  it("accepts only the verifier behind the stored challenge", async () => {
    const challenge = await codeChallenge();
    expect(await verifyPkceS256(CODE_VERIFIER, challenge)).toBe(true);
    expect(await verifyPkceS256(`${CODE_VERIFIER.slice(0, 42)}Z`, challenge)).toBe(false);
    // Too short, too long, and non-unreserved verifiers are never verified.
    expect(await verifyPkceS256("short", challenge)).toBe(false);
    expect(await verifyPkceS256("a".repeat(129), challenge)).toBe(false);
    expect(await verifyPkceS256(`${CODE_VERIFIER.slice(0, 42)} `, challenge)).toBe(false);
    expect(await verifyPkceS256(CODE_VERIFIER, "not-the-stored-challenge")).toBe(false);
  });
});

describe("authorization decision", () => {
  it("is terminal: a second decide fails and releases no second code", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const first = await approve(harness, created.requestId);

    await expectFailure(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
          outcome: "approved",
          artifact: '{"grant":"second"}',
        }),
      ),
      "relay_already_decided",
    );
    await expectFailure(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
          outcome: "rejected",
        }),
      ),
      "relay_already_decided",
    );

    // The only released code still works, and the only artifact is the first one.
    const consumed = await expectOk<{ artifactId: string }>(
      await consume(harness, first.code),
      200,
    );
    expect(consumed.artifactId).toBe(first.artifactId);
  });

  it("rejects a decision from another subject and never leaks existence", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    await expectFailure(
      await harness.handler(get(`/authorization/requests/${created.requestId}`, OTHER_OWNER_TOKEN)),
      "relay_not_found",
    );
    await expectFailure(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OTHER_OWNER_TOKEN, {
          outcome: "approved",
          artifact: "x",
        }),
      ),
      "relay_not_found",
    );
    // Still undecided for the bound owner.
    const state = await expectOk<{ decision: unknown }>(
      await harness.handler(get(`/authorization/requests/${created.requestId}`, OWNER_TOKEN)),
      200,
    );
    expect(state.decision).toBeNull();
  });

  it("refuses to decide an expired request", async () => {
    const harness = createHarness({ requestTtlMs: 1000 });
    const created = await createRequest(harness);
    harness.clock.advance(1000);

    const state = await expectOk<{ expired: boolean }>(
      await harness.handler(get(`/authorization/requests/${created.requestId}`, OWNER_TOKEN)),
      200,
    );
    expect(state.expired).toBe(true);

    await expectFailure(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
          outcome: "approved",
          artifact: "x",
        }),
      ),
      "relay_expired",
    );
    await expectFailure(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
          outcome: "rejected",
        }),
      ),
      "relay_expired",
    );
  });

  it("rejects a decision on an unknown request", async () => {
    const harness = createHarness();
    await expectFailure(
      await harness.handler(
        post("/authorization/requests/unknown-request/decision", OWNER_TOKEN, {
          outcome: "rejected",
        }),
      ),
      "relay_not_found",
    );
  });
});

describe("one-time authorization code", () => {
  it("consumes exactly once", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);

    await expectOk(await consume(harness, decision.code), 200);
    await expectFailure(await consume(harness, decision.code), "relay_code_already_consumed");
  });

  it("survives concurrent consumes with exactly one release", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);

    const responses = await Promise.all([
      consume(harness, decision.code),
      consume(harness, decision.code),
      consume(harness, decision.code),
    ]);
    const statuses = responses.map((response) => response.status).sort();
    expect(statuses).toEqual([200, 409, 409]);
  });

  it("burns the code when PKCE verification fails", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);

    await expectFailure(
      await harness.handler(
        post("/authorization/codes/consume", CLIENT_TOKEN, {
          code: decision.code,
          codeVerifier: `${CODE_VERIFIER.slice(0, 42)}Z`,
          redirectUri: REDIRECT_URI,
        }),
      ),
      "relay_code_invalid",
    );
    // The correct verifier no longer helps: a failed binding is not a retry.
    await expectFailure(await consume(harness, decision.code), "relay_code_already_consumed");
    // The burn voided the artifact the code would have released.
    await expectFailure(
      await claim(harness, decision.artifactId),
      "relay_artifact_already_claimed",
    );
  });

  it("burns the code when the redirect URI does not match", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);

    await expectFailure(
      await harness.handler(
        post("/authorization/codes/consume", CLIENT_TOKEN, {
          code: decision.code,
          codeVerifier: CODE_VERIFIER,
          redirectUri: "https://app.example/other",
        }),
      ),
      "relay_code_invalid",
    );
    await expectFailure(await consume(harness, decision.code), "relay_code_already_consumed");
  });

  it("refuses an expired code and leaves it unconsumed", async () => {
    const harness = createHarness({ codeTtlMs: 1000 });
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);
    harness.clock.advance(1000);

    await expectFailure(await consume(harness, decision.code), "relay_expired");
    await expectFailure(await consume(harness, decision.code), "relay_expired");
  });

  it("hides a code bound to another client", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);

    await expectFailure(
      await consume(harness, decision.code, OTHER_CLIENT_TOKEN),
      "relay_code_invalid",
    );
    // The bound client is unaffected.
    await expectOk(await consume(harness, decision.code), 200);
  });

  it("is not an oracle for whether a guessed code was correct", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);
    const decision = await approve(harness, created.requestId);

    // A wrong guess, another client's code, a wrong redirect URI, and a wrong
    // verifier against a real code must be indistinguishable on the wire.
    const guessed = await consume(harness, "unknown-code");
    const foreign = await consume(harness, decision.code, OTHER_CLIENT_TOKEN);
    // Each binding failure burns its own code, so the second one needs its own
    // authorization.
    const wrongRedirect = await harness.handler(
      post("/authorization/codes/consume", CLIENT_TOKEN, {
        code: decision.code,
        codeVerifier: CODE_VERIFIER,
        redirectUri: "https://app.example/other",
      }),
    );
    const second = await approve(harness, (await createRequest(harness)).requestId);
    const wrongVerifier = await harness.handler(
      post("/authorization/codes/consume", CLIENT_TOKEN, {
        code: second.code,
        codeVerifier: `${CODE_VERIFIER.slice(0, 42)}Z`,
        redirectUri: REDIRECT_URI,
      }),
    );
    for (const response of [guessed, foreign, wrongRedirect, wrongVerifier]) {
      await expectFailure(response, "relay_code_invalid");
    }
  });
});

describe("resume", () => {
  it("re-reads authorization state without transitioning anything", async () => {
    const harness = createHarness();
    const created = await createRequest(harness);

    const before = await expectOk<{ decision: unknown; expired: boolean }>(
      await harness.handler(
        post("/authorization/resume", CLIENT_TOKEN, { requestId: created.requestId }),
      ),
      200,
    );
    expect(before).toMatchObject({ decision: null, expired: false });

    const decision = await approve(harness, created.requestId);
    const after = await expectOk<{ decision: { outcome: string } }>(
      await harness.handler(
        post("/authorization/resume", CLIENT_TOKEN, { requestId: created.requestId }),
      ),
      200,
    );
    expect(after.decision).toEqual({ outcome: "approved", decidedAt: decision.decidedAt });

    // Resume released nothing: the code is still the only one and still unused.
    await expectOk(await consume(harness, decision.code), 200);
  });

  it("hides an unknown request", async () => {
    const harness = createHarness();
    await expectFailure(
      await harness.handler(post("/authorization/resume", CLIENT_TOKEN, { requestId: "unknown" })),
      "relay_not_found",
    );
  });
});
