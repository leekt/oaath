/**
 * Current-version owner-signing artifact wire owner.
 *
 * This codec captures the returned artifact into one exact immutable value and
 * enforces the current compact low-S P-256 representation. It does not verify the
 * signature, bind a signer, or authorize the request; those decisions belong
 * to the consumer of the artifact.
 *
 * @author taek <leekt216@gmail.com>
 */
import { p256 } from "@noble/curves/nist.js";
import { capturedByProtocol, type ProtocolContractErrorCode, protocolFailure } from "./errors.js";
import { type CaptureFailure, exactRecord } from "./internal/exact-record.js";

export const OAATH_OWNER_SIGNING_ARTIFACT_VERSION = "oaath.owner-signing-artifact/v1" as const;

const ERROR_CODE = "signing_artifact_invalid" satisfies ProtocolContractErrorCode;
const HASH = /^0x[0-9a-f]{64}$/u;
const COMPACT_SIGNATURE = /^0x[0-9a-f]{128}$/u;

export interface OwnerSigningArtifact {
  readonly version: typeof OAATH_OWNER_SIGNING_ARTIFACT_VERSION;
  readonly kind: "p256";
  readonly requestHash: `0x${string}`;
  readonly signature: `0x${string}`;
}

function captureHash(value: unknown, fail: CaptureFailure): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return fail("owner signing artifact requestHash must be a lowercase 32-byte hash");
  }
  return value as `0x${string}`;
}

function captureSignature(value: unknown, fail: CaptureFailure): `0x${string}` {
  if (typeof value !== "string" || !COMPACT_SIGNATURE.test(value)) {
    return fail("owner signing artifact signature must be lowercase compact P-256 hex");
  }
  let highS: boolean;
  try {
    highS = p256.Signature.fromCompact(value.slice(2)).hasHighS();
  } catch {
    return fail("owner signing artifact signature scalars are outside P-256");
  }
  if (highS) {
    return fail("owner signing artifact signature is not low-S");
  }
  return value as `0x${string}`;
}

/** Captures the exact current artifact shape without deciding whether it is authorized. */
export function parseOwnerSigningArtifact(value: unknown): Readonly<OwnerSigningArtifact> {
  return capturedByProtocol(
    ERROR_CODE,
    "owner signing artifact could not be captured safely",
    () => {
      const fail = protocolFailure(ERROR_CODE);
      const record = exactRecord(
        value,
        ["version", "kind", "requestHash", "signature"],
        "owner signing artifact",
        new WeakSet(),
        fail,
      );
      if (record.version !== OAATH_OWNER_SIGNING_ARTIFACT_VERSION || record.kind !== "p256") {
        return fail("owner signing artifact version or kind is unsupported");
      }
      return Object.freeze({
        version: OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
        kind: "p256",
        requestHash: captureHash(record.requestHash, fail),
        signature: captureSignature(record.signature, fail),
      });
    },
  );
}

/** Emits the one canonical JSON string representation in fixed field order. */
export function serializeOwnerSigningArtifact(value: unknown): string {
  const artifact = parseOwnerSigningArtifact(value);
  return JSON.stringify({
    version: artifact.version,
    kind: artifact.kind,
    requestHash: artifact.requestHash,
    signature: artifact.signature,
  });
}
