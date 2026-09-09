import { hashPermissionRequest, parsePermissionRequest } from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import {
  createHarness,
  createRequest,
  createTestKms,
  expectOk,
  get,
  LIVE_PERMISSION_POLICY,
  LIVE_PERMISSION_SCOPE,
  OWNER_TOKEN,
  post,
  TEST_CLOCK_SECONDS,
} from "./support.js";

describe("permission approval admission", () => {
  it.each([
    ["opaque text", null],
    ["another request", { requestId: "another-request" }],
    ["another request hash", { requestHash: `0x${"cc".repeat(32)}` }],
    ["future decision", { decidedAt: TEST_CLOCK_SECONDS + 1 }],
    [
      "broader policy",
      {
        approvedPolicy: {
          ...LIVE_PERMISSION_POLICY,
          calls: [{ ...LIVE_PERMISSION_POLICY.calls[0], valueLimit: "101" }],
        },
      },
    ],
    ["reject decision", { kind: "reject" }],
  ])("refuses %s before KMS or a terminal decision", async (_label, change) => {
    const baseKms = createTestKms();
    let encryptions = 0;
    const harness = createHarness({
      kms: {
        async encrypt(plaintext) {
          encryptions += 1;
          return baseKms.encrypt(plaintext);
        },
        decrypt: baseKms.decrypt,
      },
    });
    const created = await createRequest(harness, LIVE_PERMISSION_SCOPE);
    const request = parsePermissionRequest({
      ...JSON.parse(LIVE_PERMISSION_SCOPE),
      requestId: created.requestId,
    });
    const decision: Record<string, unknown> = {
      version: "oaath.permission-decision/v1",
      kind: "approve",
      requestId: created.requestId,
      requestHash: hashPermissionRequest(request),
      decidedAt: TEST_CLOCK_SECONDS,
      approvedPolicy: LIVE_PERMISSION_POLICY,
      capabilityHash: `0x${"ab".repeat(32)}`,
      ...change,
    };
    if (decision.kind === "reject") {
      delete decision.approvedPolicy;
      delete decision.capabilityHash;
    }
    const response = await harness.handler(
      post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
        outcome: "approved",
        artifact: change === null ? "opaque artifact" : JSON.stringify(decision),
      }),
    );
    expect(response.status).toBe(400);
    expect(encryptions).toBe(0);
    const pending = await expectOk<{ decision: unknown }>(
      await harness.handler(get(`/authorization/requests/${created.requestId}`, OWNER_TOKEN)),
      200,
    );
    expect(pending.decision).toBeNull();
    await expectOk(
      await harness.handler(
        post(`/authorization/requests/${created.requestId}/decision`, OWNER_TOKEN, {
          outcome: "rejected",
        }),
      ),
      200,
    );
    expect(encryptions).toBe(0);
  });
});
