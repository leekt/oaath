/**
 * Grant reference verification matrix: an active exact revision authorizes;
 * every mismatch, lifecycle denial, and unreadable record fails closed with a
 * typed code; verification is replay-safe and mutates nothing.
 *
 * @author taek <leekt216@gmail.com>
 */

import {
  type GrantVerificationResult,
  hashGrantPolicy,
  hashGrantPolicyCalls,
  OAATH_GRANT_REFERENCE_VERSION,
} from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import {
  approve,
  CLIENT_TOKEN,
  claim,
  codeChallenge,
  consume,
  createHarness,
  createRequest,
  expectFailure,
  expectOk,
  type Harness,
  LIVE_PERMISSION_POLICY,
  LIVE_PERMISSION_SCOPE,
  NO_AUDIENCE_CLIENT_TOKEN,
  OTHER_CLIENT_TOKEN,
  OWNER_TOKEN,
  post,
  REDIRECT_URI,
} from "./support.js";

const LIVE_POLICY = LIVE_PERMISSION_POLICY;
const LIVE_SCOPE = LIVE_PERMISSION_SCOPE;

const CALLS_DIGEST = hashGrantPolicyCalls(LIVE_POLICY.calls);
const POLICY_DIGEST = hashGrantPolicy(LIVE_POLICY);

function assertion(grantId: string, overrides: Record<string, unknown> = {}) {
  return {
    grantId,
    revision: 1,
    subject: "subject-1",
    clientId: "client-a",
    organizationAudience: "org-1",
    requiredCallsDigest: CALLS_DIGEST,
    ...overrides,
  };
}

function verify(
  harness: Harness,
  body: unknown,
  token: string | null = CLIENT_TOKEN,
): Promise<Response> {
  return harness.handler(post("/grants/verify", token, body));
}

async function expectResult(response: Response, expected: GrantVerificationResult): Promise<void> {
  expect(await expectOk<GrantVerificationResult>(response, 200)).toEqual(expected);
}

async function approvedGrant(harness: Harness): Promise<string> {
  const created = await createRequest(harness, LIVE_SCOPE);
  await approve(harness, created.requestId);
  return created.requestId;
}

describe("POST /grants/verify", () => {
  it("authorizes an active exact revision with immutable reference evidence", async () => {
    const harness = createHarness();
    const grantId = await approvedGrant(harness);
    await expectResult(await verify(harness, assertion(grantId)), {
      state: "authorized",
      ref: {
        version: OAATH_GRANT_REFERENCE_VERSION,
        grantId,
        revision: 1,
        subject: "subject-1",
        clientId: "client-a",
        organizationAudience: "org-1",
        state: "active",
        policyDigest: POLICY_DIGEST,
      },
    });
  });

  it("is replay-safe and does not mutate the Grant", async () => {
    const harness = createHarness();
    const created = await createRequest(harness, LIVE_SCOPE);
    // A verification before the decision answers pending and blocks nothing.
    await expectResult(await verify(harness, assertion(created.requestId)), {
      state: "denied",
      code: "grant_pending",
    });
    const approved = await approve(harness, created.requestId);
    const first = await verify(harness, assertion(created.requestId));
    const second = await verify(harness, assertion(created.requestId));
    expect(await first.json()).toEqual(await second.json());
    // The one-time consume and claim still succeed after verifications, so
    // verification wrote nothing into the authorization lifecycle.
    const consumed = await expectOk<{ artifactId: string }>(
      await consume(harness, approved.code),
      200,
    );
    await expectOk(await claim(harness, consumed.artifactId), 200);
  });

  it("denies a pending, rejected, revoked, or expired grant with typed codes", async () => {
    const harness = createHarness();

    const pending = await createRequest(harness, LIVE_SCOPE);
    await expectResult(await verify(harness, assertion(pending.requestId)), {
      state: "denied",
      code: "grant_pending",
    });

    const rejected = await createRequest(harness, LIVE_SCOPE);
    await expectOk(
      await harness.handler(
        post(`/authorization/requests/${rejected.requestId}/decision`, OWNER_TOKEN, {
          outcome: "rejected",
        }),
      ),
      200,
    );
    await expectResult(await verify(harness, assertion(rejected.requestId)), {
      state: "denied",
      code: "grant_rejected",
    });

    const revoked = await approvedGrant(harness);
    await expectOk(
      await harness.handler(
        post("/invalidations", CLIENT_TOKEN, {
          grantId: revoked,
          capabilityHash: `0x${"aa".repeat(32)}`,
        }),
      ),
      200,
    );
    await expectResult(await verify(harness, assertion(revoked)), {
      state: "denied",
      code: "grant_revoked",
    });

    const expired = await approvedGrant(harness);
    harness.clock.advance(601_000);
    await expectResult(await verify(harness, assertion(expired)), {
      state: "denied",
      code: "grant_expired",
    });
  });

  it("denies a newer or unknown revision", async () => {
    const harness = createHarness();
    const grantId = await approvedGrant(harness);
    await expectResult(await verify(harness, assertion(grantId, { revision: 2 })), {
      state: "denied",
      code: "grant_revision_mismatch",
    });
  });

  it("denies mismatched subject, client, and audience assertions", async () => {
    const harness = createHarness();
    const grantId = await approvedGrant(harness);
    await expectResult(await verify(harness, assertion(grantId, { subject: "subject-2" })), {
      state: "denied",
      code: "grant_subject_mismatch",
    });
    await expectResult(await verify(harness, assertion(grantId, { clientId: "client-b" })), {
      state: "denied",
      code: "grant_client_mismatch",
    });
    await expectResult(
      await verify(harness, assertion(grantId, { organizationAudience: "org-2" })),
      { state: "denied", code: "grant_audience_mismatch" },
    );
  });

  it("denies every audience assertion when the deployment declared none", async () => {
    const harness = createHarness();
    const created = await expectOk<{ requestId: string }>(
      await harness.handler(
        post("/authorization/requests", NO_AUDIENCE_CLIENT_TOKEN, {
          redirectUri: REDIRECT_URI,
          codeChallenge: await codeChallenge(),
          requestedScope: LIVE_SCOPE,
        }),
      ),
      201,
    );
    await approve(harness, created.requestId);
    await expectResult(await verify(harness, assertion(created.requestId)), {
      state: "denied",
      code: "grant_audience_mismatch",
    });
  });

  it("denies an uncovered call set", async () => {
    const harness = createHarness();
    const grantId = await approvedGrant(harness);
    const narrower = hashGrantPolicyCalls([{ ...LIVE_POLICY.calls[0], valueLimit: "1" }]);
    await expectResult(
      await verify(harness, assertion(grantId, { requiredCallsDigest: narrower })),
      { state: "denied", code: "grant_calls_mismatch" },
    );
  });

  it("answers unknown for an absent grant and for another client's grant", async () => {
    const harness = createHarness();
    const grantId = await approvedGrant(harness);
    await expectResult(await verify(harness, assertion("no-such-grant")), {
      state: "unknown",
      code: "grant_unknown",
    });
    // client-b learns absence, never existence, state, or a binding fact.
    await expectResult(
      await verify(harness, assertion(grantId, { clientId: "client-b" }), OTHER_CLIENT_TOKEN),
      { state: "unknown", code: "grant_unknown" },
    );
  });

  it("answers unknown, never authorized, for an unreadable stored scope", async () => {
    const harness = createHarness();
    const unreadable = await createRequest(harness, '{"not":"a permission request"}');
    await approve(harness, unreadable.requestId).catch(() => undefined);
    await expectResult(await verify(harness, assertion(unreadable.requestId)), {
      state: "unknown",
      code: "grant_unreadable",
    });

    // A scope whose own application binding contradicts the authenticated
    // creator is contradictory evidence and fails closed the same way.
    const contradictory = JSON.parse(LIVE_SCOPE) as {
      application: { clientId: string };
    };
    contradictory.application.clientId = "client-b";
    const created = await createRequest(harness, JSON.stringify(contradictory));
    await expectResult(await verify(harness, assertion(created.requestId)), {
      state: "unknown",
      code: "grant_unreadable",
    });
  });

  it("refuses malformed assertions and wrong roles at the wire", async () => {
    const harness = createHarness();
    const grantId = await approvedGrant(harness);
    const { requiredCallsDigest: _omitted, ...missingDigest } = assertion(grantId);
    await expectFailure(await verify(harness, missingDigest), "relay_request_invalid");
    await expectFailure(
      await verify(harness, assertion(grantId, { revision: 0 })),
      "relay_request_invalid",
    );
    await expectFailure(await verify(harness, assertion(grantId), null), "relay_unauthenticated");
    await expectFailure(await verify(harness, assertion(grantId), OWNER_TOKEN), "relay_forbidden");
  });
});
