import { p256 } from "@noble/curves/nist.js";
import {
  hashKernelV4RevocationSigningRequest,
  hashOwnerSigningRequest,
  parseKernelV4RevocationSigningRequest,
  parsePermissionRequest,
} from "@oaath/protocol";
import { bytesToHex, hexToBytes } from "viem";
import { describe, expect, it } from "vitest";
import { observeKernelPermissionRevocation } from "../src/kernel/permission/observe-revocation.js";
import {
  encodeKernelV4Execution,
  encodeKernelV4InstallNonceInvalidationCall,
  encodeKernelV4PermissionUninstallCalls,
  prepareKernelPhonePermissionApproval,
  prepareKernelPhoneRevocation,
  restoreKernelPhoneRevocation,
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
  it("observes only finalized absence with the consumed approval nonce on its own chain", async () => {
    const { input } = await fixture();
    const binding = {
      chainId: CHAIN_ID,
      account: input.approval.account,
      permissionId: "0x11223344" as const,
    };
    const block = { number: "0x10", hash: `0x${"aa".repeat(32)}` };
    for (const mode of [
      "valid",
      "absent-nonce",
      "unused-nonce",
      "foreign-key",
      "present",
      "reorg",
      "foreign-chain",
    ] as const) {
      const seen: string[] = [];
      const proof = await observeKernelPermissionRevocation({
        binding,
        approval: input.approval,
        now: () => 120,
        observation: {
          close: async () => {
            throw new Error("borrowed observation must not close");
          },
          async read(request) {
            seen.push(request.type);
            expect(request.chainId).toBe(CHAIN_ID);
            if (request.type === "chain_id") return mode === "foreign-chain" ? 1 : CHAIN_ID;
            if (request.type === "finalized_block") return block;
            if (request.type === "canonical_block")
              return mode === "reorg" ? { ...block, hash: `0x${"bb".repeat(32)}` } : block;
            if (
              request.type === "kernel_permission_installed" ||
              request.type === "kernel_install_nonce"
            ) {
              expect(request.account).toBe(binding.account);
              expect(request.blockNumber).toBe("16");
              if (request.type === "kernel_permission_installed") {
                expect(request.permissionId).toBe(binding.permissionId);
                return mode === "present";
              }
              expect(request.nonce).toBe(input.approval.installNonce);
              if (mode === "absent-nonce") return "0x";
              const increment =
                mode === "unused-nonce" ? 0n : mode === "foreign-key" ? 1n << 64n : 1n;
              return `0x${(BigInt(request.nonce) + increment).toString(16).padStart(64, "0")}`;
            }
            throw new Error("unexpected effect read");
          },
        },
      });
      if (mode === "valid") {
        expect(proof).toMatchObject({
          permission: { ...binding, kind: "permission_absent", blockNumber: "16", observedAt: 120 },
          installNonce: (BigInt(input.approval.installNonce) + 1n).toString(10),
        });
        expect(seen).toHaveLength(5);
      } else expect(proof).toBeNull();
    }
  });

  it.each(["invalidate-install", "uninstall-permission"] as const)(
    "prepares only %s calls and completes the exact phone signature",
    async (effect) => {
      const { input, sign } = await fixture();
      const value = { ...input, effect };
      const prepared = await prepareKernelPhoneRevocation(value);
      const recreated = restoreKernelPhoneRevocation(
        JSON.parse(JSON.stringify(prepared.signingRequest)),
      );
      expect(recreated.signingRequest).toEqual(prepared.signingRequest);
      expect(recreated.prepared).toEqual(prepared.prepared);
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
    const original = await prepareKernelPhoneRevocation(input);
    const first = restoreKernelPhoneRevocation(JSON.parse(JSON.stringify(original.signingRequest)));
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
