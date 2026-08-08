import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  createKernelV4ReplayableInstallTypedData,
  hashCanonicalEip712TypedData,
  hashOwnerSigningRequest,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
  OAATH_OWNER_SIGNING_REQUEST_VERSION,
  type OwnerSigningArtifact,
  parseOwnerSigningArtifact,
  serializeOwnerSigningArtifact,
} from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import { verifyKernelV4ReplayableInstallOwnerSigningArtifact } from "../src/authorization/owner-signing.js";
import { OaathRelayError } from "../src/relay/errors.js";
import { RELAY_LIMITS } from "../src/store/records.js";

const ACCOUNT = `0x${"11".repeat(20)}` as const;
const MODULE = `0x${"22".repeat(20)}` as const;

interface Fixture {
  readonly request: unknown;
  readonly artifact: Readonly<OwnerSigningArtifact>;
  readonly canonical: string;
}

function createFixture(signWrongDigest = false): Fixture {
  const privateKey = p256.utils.randomPrivateKey();
  try {
    const publicKey = `0x${bytesToHex(p256.getPublicKey(privateKey, false))}` as const;
    const typedData = createKernelV4ReplayableInstallTypedData({
      account: ACCOUNT,
      nonce: "0",
      packages: [
        {
          moduleType: 1,
          module: MODULE,
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
        account: ACCOUNT,
        ownerCredential: Object.freeze({
          version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
          kind: "p256" as const,
          publicKey,
        }),
      }),
      typedData,
      expectedDigest,
      replay: Object.freeze({ nonce: "0", deadline: null }),
    });
    const digest = hexToBytes(expectedDigest.slice(2));
    if (signWrongDigest) digest[0] = (digest[0] ?? 0) ^ 1;
    const signature = p256.sign(digest, privateKey, {
      lowS: true,
      prehash: false,
    });
    const artifact = Object.freeze({
      version: OAATH_OWNER_SIGNING_ARTIFACT_VERSION,
      kind: "p256" as const,
      requestHash: hashOwnerSigningRequest(request),
      signature: `0x${signature.toCompactHex()}` as const,
    });
    return Object.freeze({
      request,
      artifact,
      canonical: serializeOwnerSigningArtifact(artifact),
    });
  } finally {
    privateKey.fill(0);
  }
}

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectInvalid(request: unknown, artifactPlaintext: unknown): void {
  let invalid = false;
  try {
    verifyKernelV4ReplayableInstallOwnerSigningArtifact(request, artifactPlaintext);
  } catch (error) {
    invalid = error instanceof OaathRelayError && error.code === "relay_request_invalid";
  }
  expect(invalid).toBe(true);
}

function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

describe("Kernel v4 owner-signing artifact verification", () => {
  it("returns only the canonical artifact after every exact binding verifies", () => {
    const fixture = createFixture();
    const verified = verifyKernelV4ReplayableInstallOwnerSigningArtifact(
      fixture.request,
      fixture.canonical,
    );
    const parsed = parseOwnerSigningArtifact(JSON.parse(verified) as unknown);

    expect(verified === fixture.canonical).toBe(true);
    expect(
      Object.keys(JSON.parse(verified) as object).join(",") ===
        "version,kind,requestHash,signature",
    ).toBe(true);
    expect(parsed.requestHash === hashOwnerSigningRequest(fixture.request)).toBe(true);
    expect(parsed.signature.length === 130).toBe(true);
  });

  it("rejects every noncanonical, unbound, wrongly signed, or unsupported input", () => {
    const fixture = createFixture();
    const reordered = JSON.stringify({
      kind: fixture.artifact.kind,
      version: fixture.artifact.version,
      requestHash: fixture.artifact.requestHash,
      signature: fixture.artifact.signature,
    });
    const duplicateRequestHash =
      `{"version":${JSON.stringify(fixture.artifact.version)},` +
      `"kind":${JSON.stringify(fixture.artifact.kind)},` +
      `"requestHash":${JSON.stringify(fixture.artifact.requestHash)},` +
      `"requestHash":${JSON.stringify(fixture.artifact.requestHash)},` +
      `"signature":${JSON.stringify(fixture.artifact.signature)}}`;
    const compact = fixture.artifact.signature.slice(2);
    const highS = `0x${compact.slice(0, 64)}${word(
      p256.CURVE.n - BigInt(`0x${compact.slice(64)}`),
    )}`;
    const structurallyInvalid = [
      null,
      "",
      "{",
      "null",
      "x".repeat(RELAY_LIMITS.artifactPlaintext + 1),
      ` ${fixture.canonical}`,
      `\n${fixture.canonical}`,
      reordered,
      duplicateRequestHash,
      JSON.stringify({ ...fixture.artifact, extra: true }),
      JSON.stringify({ ...fixture.artifact, version: "oaath.owner-signing-artifact/v2" }),
      JSON.stringify({ ...fixture.artifact, kind: "ecdsa" }),
      JSON.stringify({ ...fixture.artifact, signature: fixture.artifact.signature.toUpperCase() }),
      JSON.stringify({ ...fixture.artifact, signature: highS }),
    ];
    for (const artifact of structurallyInvalid) expectInvalid(fixture.request, artifact);

    const wrongRequestHash = serializeOwnerSigningArtifact({
      ...fixture.artifact,
      requestHash: `${fixture.artifact.requestHash.slice(0, -1)}${
        fixture.artifact.requestHash.endsWith("0") ? "1" : "0"
      }`,
    });
    expectInvalid(fixture.request, wrongRequestHash);

    const foreign = createFixture();
    const wrongKey = serializeOwnerSigningArtifact({
      ...foreign.artifact,
      requestHash: hashOwnerSigningRequest(fixture.request),
    });
    expectInvalid(fixture.request, wrongKey);

    const wrongDigest = createFixture(true);
    expectInvalid(wrongDigest.request, wrongDigest.canonical);

    const ecdsa = clone(fixture.request) as {
      signer: { ownerCredential: unknown };
    };
    ecdsa.signer.ownerCredential = {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: `0x${"33".repeat(20)}`,
    };
    const webauthn = clone(fixture.request) as {
      signer: { ownerCredential: unknown };
    };
    webauthn.signer.ownerCredential = {
      version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn",
      publicKey: (fixture.request as { signer: { ownerCredential: { publicKey: string } } }).signer
        .ownerCredential.publicKey,
      authenticatorIdHash: `0x${"44".repeat(32)}`,
    };
    for (const request of [ecdsa, webauthn]) expectInvalid(request, fixture.canonical);

    for (const purpose of ["permit", "permit2", "application"]) {
      const request = clone(fixture.request) as { purpose: string };
      request.purpose = purpose;
      expectInvalid(request, fixture.canonical);
    }

    const rawDigest = {
      version: OAATH_OWNER_SIGNING_REQUEST_VERSION,
      kind: "raw-digest",
      digest: (fixture.request as { expectedDigest: string }).expectedDigest,
      reason: "Caller supplied only a digest",
      decision: "reject-only",
    };
    expectInvalid(rawDigest, fixture.canonical);

    const wrongAccount = clone(fixture.request) as { signer: { account: string } };
    wrongAccount.signer.account = `0x${"55".repeat(20)}`;
    const wrongReplay = clone(fixture.request) as { replay: { nonce: string } };
    wrongReplay.replay.nonce = "1";
    const wrongExpectedDigest = clone(fixture.request) as { expectedDigest: string };
    wrongExpectedDigest.expectedDigest = `0x${"66".repeat(32)}`;
    const wrongDomain = clone(fixture.request) as { typedData: { domain: { name: string } } };
    wrongDomain.typedData.domain.name = "Not Kernel";
    for (const request of [wrongAccount, wrongReplay, wrongExpectedDigest, wrongDomain]) {
      expectInvalid(request, fixture.canonical);
    }

    const generic = clone(fixture.request) as {
      typedData: unknown;
      expectedDigest: `0x${string}`;
    };
    generic.typedData = {
      types: {
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
          { name: "verifyingContract", type: "address" },
        ],
        Application: [{ name: "value", type: "bytes32" }],
      },
      primaryType: "Application",
      domain: { name: "Application", version: "1", verifyingContract: ACCOUNT },
      message: { value: `0x${"77".repeat(32)}` },
    };
    generic.expectedDigest = hashCanonicalEip712TypedData(generic.typedData);
    expectInvalid(generic, fixture.canonical);
  });
});
