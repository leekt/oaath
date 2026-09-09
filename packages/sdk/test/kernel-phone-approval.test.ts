import { p256 } from "@noble/curves/nist.js";
import {
  applyPermissionDecision,
  createGrantFromPermissionRequest,
  hashOwnerSigningRequest,
  hashPermissionRequest,
  type PermissionRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { bytesToHex, hexToBytes } from "viem";
import { describe, expect, it } from "vitest";
import {
  kernelAllChainCapabilityHash,
  prepareKernelPhonePermissionApproval,
} from "../src/kernel.js";
import {
  accountProfile,
  CHAIN_ID,
  createChainFixture,
  operatorCredential,
  workspaceContext,
} from "./support/browser.js";

function fixture() {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = bytesToHex(p256.getPublicKey(privateKey, false));
  const request = parsePermissionRequest({
    version: "oaath.permission-request/v2",
    requestId: "phone-permission-1",
    context: workspaceContext,
    application: {
      applicationId: "app-1",
      clientId: "client-a",
      origin: "https://app.example",
      deviceId: "device-1",
    },
    chainScope: "all",
    logicalAccount: {
      ...accountProfile,
      ownerCredential: { version: "oaath.owner-credential-profile/v1", kind: "p256", publicKey },
    },
    operatorCredential,
    sessionSigner: null,
    policy: {
      version: "oaath.grant-policy/v1",
      calls: [
        {
          target: `0x${"44".repeat(20)}`,
          selector: "0xa9059cbb",
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
  const reads = createChainFixture().capability.reads;
  const prepare = (value: Readonly<PermissionRequest> = request, installNonce = "0") =>
    prepareKernelPhonePermissionApproval({
      request: value,
      chainId: CHAIN_ID,
      reads,
      installNonce,
    });
  const sign = (prepared: Awaited<ReturnType<typeof prepare>>) => ({
    version: "oaath.owner-signing-artifact/v1" as const,
    kind: "p256" as const,
    requestHash: hashOwnerSigningRequest(prepared.signingRequest),
    signature: bytesToHex(
      p256
        .sign(hexToBytes(prepared.signingRequest.expectedDigest), privateKey, {
          prehash: false,
          lowS: true,
        })
        .toCompactRawBytes(),
    ),
  });
  return { request, prepare, sign, publicKey };
}

describe("canonical permission approval for the owner phone", () => {
  it("completes a phone signature into the existing applicable grant artifact", async () => {
    const fixed = fixture();
    const prepared = await fixed.prepare();
    expect(prepared.request.context).toEqual(fixed.request.context);
    expect(prepared.signingRequest.purpose).toBe("kernel-enable");
    const artifact = await prepared.complete(fixed.sign(prepared), 110);
    const { installApproval, ...decision } = artifact;
    expect(decision.requestHash).toBe(hashPermissionRequest(fixed.request));
    expect(decision.approvedPolicy).toEqual(fixed.request.policy);
    expect(decision.capabilityHash).toBe(kernelAllChainCapabilityHash(installApproval));
    expect(installApproval.digest).toBe(prepared.signingRequest.expectedDigest);
    expect(
      p256.verify(
        hexToBytes(installApproval.enableSignature),
        hexToBytes(installApproval.digest),
        hexToBytes(fixed.publicKey),
        {
          prehash: false,
          lowS: true,
        },
      ),
    ).toBe(true);
    const applied = applyPermissionDecision({
      request: fixed.request,
      grant: createGrantFromPermissionRequest(fixed.request),
      observation: { status: "available", decision },
      evaluatedAt: 110,
    });
    expect(applied.status === "applied" && applied.grant.state === "approved").toBe(true);
  });

  it("recreates the same signing request without retained runtime state", async () => {
    const fixed = fixture();
    const first = await fixed.prepare();
    const second = await fixed.prepare();
    expect(second.signingRequest).toEqual(first.signingRequest);
    await second.complete(fixed.sign(first), 110);
  });

  it("derives WebAuthn session packages without a session authenticator", async () => {
    const fixed = fixture();
    const request = parsePermissionRequest({
      ...fixed.request,
      operatorCredential: {
        version: "oaath.operator-credential-profile/v1",
        kind: "webauthn",
        publicKey: fixed.publicKey,
        authenticatorIdHash: `0x${"22".repeat(32)}`,
      },
    });
    const prepared = await fixed.prepare(request);
    const artifact = await prepared.complete(fixed.sign(prepared), 110);
    expect(artifact.requestHash).toBe(hashPermissionRequest(request));
  });

  it("rejects a signature artifact for another install request", async () => {
    const fixed = fixture();
    const first = await fixed.prepare();
    const other = await fixed.prepare(fixed.request, "1");
    await expect(first.complete(fixed.sign(other), 110)).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
    const relabeled = {
      ...fixed.sign(other),
      requestHash: hashOwnerSigningRequest(first.signingRequest),
    };
    await expect(first.complete(relabeled, 110)).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
  });

  it.each([99, 191, 200])(
    "rejects an approval outside the usable window at %i",
    async (decidedAt) => {
      const fixed = fixture();
      const prepared = await fixed.prepare();
      await expect(prepared.complete(fixed.sign(prepared), decidedAt)).rejects.toMatchObject({
        code: "kernel_runtime_input_invalid",
      });
    },
  );

  it("refuses unsupported owner or policy before preparing phone approval", async () => {
    const fixed = fixture();
    await expect(
      fixed.prepare({ ...fixed.request, logicalAccount: accountProfile }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
    await expect(
      fixed.prepare({
        ...fixed.request,
        policy: {
          ...fixed.request.policy,
          calls: fixed.request.policy.calls.map((call) => ({
            ...call,
            argumentEquals: [{ index: 0, value: `0x${"11".repeat(32)}` as const }],
          })),
        },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_policy_unavailable" });
  });
});
