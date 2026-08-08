/**
 * Process-local Kernel owner-approval input for decision-path tests.
 *
 * Private and signature material is generated only in memory, never logged,
 * snapshotted, or committed. Production protocol owners build and serialize
 * every exact artifact shape used here.
 *
 * @author taek <leekt216@gmail.com>
 */

import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  createKernelV4ReplayableInstallTypedData,
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";

export interface KernelOwnerApprovalInput {
  readonly requestedScope: string;
  readonly canonicalArtifact: string;
}

export function createKernelOwnerApprovalInput(): KernelOwnerApprovalInput {
  const privateKey = p256.utils.randomPrivateKey();
  try {
    const account = `0x${"66".repeat(20)}` as const;
    const typedData = createKernelV4ReplayableInstallTypedData({
      account,
      nonce: "0",
      packages: [
        {
          moduleType: 1,
          module: `0x${"77".repeat(20)}`,
          moduleData: "0x",
          internalData: "0x",
        },
      ],
    });
    const expectedDigest = hashCanonicalEip712TypedData(typedData);
    const request = Object.freeze({
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "eip712" as const,
      purpose: "kernel-enable" as const,
      signer: Object.freeze({
        account,
        ownerCredential: Object.freeze({
          version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
          kind: "p256" as const,
          publicKey: `0x${bytesToHex(p256.getPublicKey(privateKey, false))}` as const,
        }),
      }),
      typedData,
      expectedDigest,
      replay: Object.freeze({ nonce: "0", deadline: null }),
    });
    const signature = p256.sign(hexToBytes(expectedDigest.slice(2)), privateKey, {
      lowS: true,
      prehash: false,
    });
    const canonicalArtifact = serializeOwnerSigningArtifact({
      version: OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
      kind: "p256",
      requestHash: hashOwnerSigningRequest(request),
      signature: `0x${signature.toCompactHex()}`,
    });
    return Object.freeze({ requestedScope: JSON.stringify(request), canonicalArtifact });
  } finally {
    privateKey.fill(0);
  }
}
