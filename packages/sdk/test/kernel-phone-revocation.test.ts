import { p256 } from "@noble/curves/nist.js";
import {
  hashKernelV4RevocationSigningRequest,
  hashOwnerSigningRequest,
  parseKernelV4RevocationSigningRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { bytesToHex, hexToBytes } from "viem";
import { describe, expect, it } from "vitest";
import {
  encodeKernelV4Execution,
  encodeKernelV4InstallNonceInvalidationCall,
  encodeKernelV4PermissionUninstallCalls,
  prepareKernelPhonePermissionApproval,
  prepareKernelPhoneRevocation,
} from "../src/kernel.js";
import {
  accountProfile,
  CHAIN_ID,
  createChainFixture,
  operatorCredential,
  workspaceContext,
} from "./support/browser.js";

const gas = {
  callGasLimit: "900000",
  verificationGasLimit: "3000000",
  preVerificationGas: "150000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
};

async function fixture() {
  const secret = p256.utils.randomPrivateKey();
  const request = parsePermissionRequest({
    version: "oaath.permission-request/v2",
    requestId: "phone-revocation-1",
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
      ownerCredential: {
        version: "oaath.owner-credential-profile/v1",
        kind: "p256",
        publicKey: bytesToHex(p256.getPublicKey(secret, false)),
      },
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
  const sign = (digest: `0x${string}`, requestHash: `0x${string}`) => ({
    version: "oaath.owner-signing-artifact/v1" as const,
    kind: "p256" as const,
    requestHash,
    signature: bytesToHex(
      p256.sign(hexToBytes(digest), secret, { prehash: false, lowS: true }).toCompactRawBytes(),
    ),
  });
  const permission = await prepareKernelPhonePermissionApproval({
    request,
    chainId: CHAIN_ID,
    reads,
  });
  const approved = await permission.complete(
    sign(
      permission.signingRequest.expectedDigest,
      hashOwnerSigningRequest(permission.signingRequest),
    ),
    110,
  );
  const input = {
    request,
    approval: approved.installApproval,
    chainId: CHAIN_ID,
    reads,
    effect: "invalidate-install" as const,
    nonceKey: "0",
    sequence: "0",
    gas,
  };
  return { input, sign };
}

describe("phone revocation preparation", () => {
  it.each(["invalidate-install", "uninstall-permission"] as const)(
    "prepares only %s calls and completes the exact phone signature",
    async (effect) => {
      const { input, sign } = await fixture();
      const value = { ...input, effect };
      const prepared = await prepareKernelPhoneRevocation(value);
      const recreated = await prepareKernelPhoneRevocation(value);
      expect(recreated.signingRequest).toEqual(prepared.signingRequest);
      expect(prepared.prepared.kind).toBe("revocation");
      expect(prepared.prepared.userOperation.callData).toBe(
        encodeKernelV4Execution({
          calls:
            effect === "invalidate-install"
              ? [
                  encodeKernelV4InstallNonceInvalidationCall({
                    account: input.approval.account,
                    installNonce: input.approval.installNonce,
                  }),
                ]
              : encodeKernelV4PermissionUninstallCalls({
                  account: input.approval.account,
                  packages: input.approval.packages,
                }),
        }),
      );
      expect(prepared.signingRequest.expectedDigest).toBe(prepared.prepared.userOperationHash);
      const artifact = sign(
        prepared.signingRequest.expectedDigest,
        hashKernelV4RevocationSigningRequest(prepared.signingRequest),
      );
      expect(await recreated.complete(artifact)).toBe(artifact.signature);
    },
  );

  it("rejects execution calldata in a revocation request", async () => {
    const { input } = await fixture();
    const prepared = await prepareKernelPhoneRevocation(input);
    expect(() =>
      parseKernelV4RevocationSigningRequest({
        ...prepared.signingRequest,
        operation: {
          ...prepared.signingRequest.operation,
          callData: encodeKernelV4Execution({
            calls: [{ target: `0x${"44".repeat(20)}`, value: "1", data: "0x" }],
          }),
        },
      }),
    ).toThrowError(expect.objectContaining({ code: "signing_request_invalid" }));
  });

  it("rejects another operation's artifact, including a relabeled signature", async () => {
    const { input, sign } = await fixture();
    const first = await prepareKernelPhoneRevocation(input);
    const other = await prepareKernelPhoneRevocation({ ...input, sequence: "1" });
    const artifact = sign(
      other.signingRequest.expectedDigest,
      hashKernelV4RevocationSigningRequest(other.signingRequest),
    );
    await expect(first.complete(artifact)).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
    await expect(
      first.complete({
        ...artifact,
        requestHash: hashKernelV4RevocationSigningRequest(first.signingRequest),
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_signature_invalid" });
  });

  it("refuses an approval belonging to a different canonical request", async () => {
    const { input } = await fixture();
    await expect(
      prepareKernelPhoneRevocation({
        ...input,
        request: { ...input.request, requestId: "other-grant" },
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_input_invalid" });
  });
});
