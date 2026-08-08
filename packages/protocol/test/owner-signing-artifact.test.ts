import { randomBytes } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";
import {
  OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
  OaathProtocolError,
  parseOwnerSigningArtifact,
  serializeOwnerSigningArtifact,
} from "../src/index.js";

const P256_ORDER = p256.CURVE.n;
const P256_HALF_ORDER = P256_ORDER / 2n;

function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

function runtimeArtifact() {
  const privateKey = p256.utils.randomPrivateKey();
  const digest = randomBytes(32);
  const signature = p256.sign(digest, privateKey, { lowS: true, prehash: false });
  return {
    privateKey,
    digest,
    artifact: {
      version: OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
      kind: "p256" as const,
      requestHash: `0x${randomBytes(32).toString("hex")}` as const,
      signature: `0x${signature.toCompactHex()}` as const,
    },
  };
}

function expectInvalid(value: unknown): void {
  try {
    parseOwnerSigningArtifact(value);
    throw new Error("expected owner signing artifact to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code: "signing_artifact_invalid" });
  }
}

describe("owner signing artifact", () => {
  it("captures and canonically serializes one runtime-generated compact low-S signature", () => {
    const { artifact } = runtimeArtifact();
    const shuffled = {
      signature: artifact.signature,
      requestHash: artifact.requestHash,
      kind: artifact.kind,
      version: artifact.version,
    };

    const parsed = parseOwnerSigningArtifact(shuffled);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(parsed.version).toBe(OAATH_OWNER_SIGNING_ARTIFACT_VERSION);
    expect(parsed.kind).toBe("p256");
    expect(parsed.requestHash === artifact.requestHash).toBe(true);
    expect(parsed.signature === artifact.signature).toBe(true);

    const serialized = serializeOwnerSigningArtifact(shuffled);
    const expected =
      `{"version":"${OAATH_OWNER_SIGNING_ARTIFACT_VERSION}","kind":"p256",` +
      `"requestHash":"${artifact.requestHash}","signature":"${artifact.signature}"}`;
    expect(serialized === expected).toBe(true);
    const roundTrip = parseOwnerSigningArtifact(JSON.parse(serialized));
    expect(roundTrip.requestHash === artifact.requestHash).toBe(true);
    expect(roundTrip.signature === artifact.signature).toBe(true);
  });

  it("keeps cryptographic key and digest verification outside the structural codec", () => {
    const { privateKey, digest, artifact } = runtimeArtifact();
    const wrongPrivateKey = p256.utils.randomPrivateKey();
    const wrongPublicKey = p256.getPublicKey(wrongPrivateKey, false);
    expect(
      p256.verify(artifact.signature.slice(2), digest, wrongPublicKey, {
        format: "compact",
        lowS: true,
        prehash: false,
      }),
    ).toBe(false);
    expect(
      p256.verify(artifact.signature.slice(2), digest, p256.getPublicKey(privateKey, false), {
        format: "compact",
        lowS: true,
        prehash: false,
      }),
    ).toBe(true);

    const parsed = parseOwnerSigningArtifact(artifact);
    expect(parsed.signature.length).toBe(130);
  });

  it("rejects unsupported shapes, hostile records, and noncanonical hex", () => {
    const { artifact } = runtimeArtifact();
    const hostile = Object.defineProperty({ ...artifact }, "signature", {
      enumerable: true,
      get: () => {
        throw new Error("hostile getter");
      },
    });
    const throwingProxy = new Proxy(artifact, {
      ownKeys: () => {
        throw new Error("hostile reflection");
      },
    });
    const cases: unknown[] = [
      null,
      [],
      { ...artifact, version: "oaath.owner-signing-artifact/v2" },
      { ...artifact, kind: "ecdsa" },
      { ...artifact, extra: true },
      { version: artifact.version, kind: artifact.kind, requestHash: artifact.requestHash },
      { ...artifact, requestHash: artifact.requestHash.toUpperCase() },
      { ...artifact, requestHash: artifact.requestHash.slice(0, -2) },
      { ...artifact, requestHash: `0x${"gg".repeat(32)}` },
      { ...artifact, signature: artifact.signature.toUpperCase() },
      { ...artifact, signature: artifact.signature.slice(0, -2) },
      { ...artifact, signature: `0x${"gg".repeat(64)}` },
      hostile,
      throwingProxy,
    ];
    for (const value of cases) expectInvalid(value);

    expect(() => serializeOwnerSigningArtifact({ ...artifact, extra: true })).toThrowError(
      expect.objectContaining({ code: "signing_artifact_invalid" }),
    );
  });

  it("rejects zero, out-of-range, and high-S P-256 components", () => {
    const { artifact } = runtimeArtifact();
    const signature = (r: bigint, s: bigint) => `0x${word(r)}${word(s)}`;
    for (const invalid of [
      signature(0n, 1n),
      signature(1n, 0n),
      signature(P256_ORDER, 1n),
      signature(1n, P256_ORDER),
      signature(P256_ORDER + 1n, 1n),
      signature(1n, P256_ORDER + 1n),
      signature(1n, P256_HALF_ORDER + 1n),
    ]) {
      expectInvalid({ ...artifact, signature: invalid });
    }

    expect(
      parseOwnerSigningArtifact({
        ...artifact,
        signature: signature(P256_ORDER - 1n, P256_HALF_ORDER),
      }).signature.length,
    ).toBe(130);
  });
});
