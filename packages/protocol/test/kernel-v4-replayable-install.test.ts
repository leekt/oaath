import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  createKernelV4ReplayableInstallTypedData,
  hashCanonicalEip712TypedData,
  KERNEL_V4_INSTALL_COMPONENTS,
  OaathProtocolError,
  parseKernelV4InstallPackages,
  parseKernelV4ReplayableInstallOwnerSigningRequest,
} from "../src/index.js";

interface GoldenKernelEnableRequest {
  readonly purpose: string;
  readonly signer: {
    readonly account: `0x${string}`;
    readonly ownerCredential: Readonly<Record<string, unknown>>;
  };
  readonly typedData: {
    readonly types: Readonly<Record<string, readonly Readonly<Record<string, string>>[]>>;
    readonly primaryType: string;
    readonly domain: Readonly<Record<string, unknown>>;
    readonly message: {
      readonly nonce: string;
      readonly packages: readonly Readonly<{
        readonly moduleType: string;
        readonly module: `0x${string}`;
        readonly moduleData: `0x${string}`;
        readonly internalData: `0x${string}`;
      }>[];
    };
  };
  readonly expectedDigest: `0x${string}`;
  readonly replay: { readonly nonce: string | null; readonly deadline: string | null };
}

const GOLDEN = (
  JSON.parse(
    readFileSync(
      new URL("../../server/test/fixtures/owner-phone-golden.json", import.meta.url),
      "utf8",
    ),
  ) as {
    readonly projection: {
      readonly kernelEnableOwnerSigningRequest: {
        readonly scope: { readonly request: GoldenKernelEnableRequest };
      };
    };
  }
).projection.kernelEnableOwnerSigningRequest.scope.request;

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectInvalid(value: unknown): void {
  try {
    parseKernelV4ReplayableInstallOwnerSigningRequest(value);
    throw new Error("expected Kernel enable request to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(OaathProtocolError);
    expect(error).toMatchObject({ code: "signing_request_invalid" });
  }
}

function numericPackages() {
  return GOLDEN.typedData.message.packages.map((install) => ({
    moduleType: Number(install.moduleType) as 1 | 2 | 3 | 4 | 5 | 6,
    module: install.module,
    moduleData: install.moduleData,
    internalData: install.internalData,
  }));
}

function rehash(request: GoldenKernelEnableRequest): void {
  (request as { expectedDigest: `0x${string}` }).expectedDigest = hashCanonicalEip712TypedData(
    request.typedData,
  );
}

describe("Kernel v4 replayable-install signing profile", () => {
  it("builds and recognizes the accepted chainless Kernel 0.4.0 install value", () => {
    const typedData = createKernelV4ReplayableInstallTypedData({
      account: GOLDEN.signer.account,
      nonce: GOLDEN.typedData.message.nonce,
      packages: numericPackages(),
    });

    expect(typedData).toEqual(GOLDEN.typedData);
    expect(hashCanonicalEip712TypedData(typedData)).toBe(
      "0x72781421bec5030685dd2cde6d64eb4e63ea204ddb9951bd74986b0edd69ed03",
    );
    expect(Object.isFrozen(typedData)).toBe(true);
    expect(typedData.types.Install).toBe(KERNEL_V4_INSTALL_COMPONENTS);
    expect(Object.isFrozen(typedData.types.Install)).toBe(true);
    expect(Object.isFrozen(typedData.message.packages)).toBe(true);

    const request = parseKernelV4ReplayableInstallOwnerSigningRequest(GOLDEN);
    expect(request.purpose).toBe("kernel-enable");
    expect(request.replay).toEqual({ nonce: "0", deadline: null });
  });

  it("keeps credential kind orthogonal to the exact Kernel install value", () => {
    const request = clone(GOLDEN);
    (request.signer as { ownerCredential: Readonly<Record<string, unknown>> }).ownerCredential = {
      version: "oaath.owner-credential-profile/v1",
      kind: "ecdsa",
      address: "0x2222222222222222222222222222222222222222",
    };

    expect(
      parseKernelV4ReplayableInstallOwnerSigningRequest(request).signer.ownerCredential,
    ).toEqual(request.signer.ownerCredential);
  });

  it("rejects a correctly hashed generic EIP-712 request relabelled as Kernel enable", () => {
    const request = clone(GOLDEN);
    (request as unknown as { typedData: unknown }).typedData = {
      types: {
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
          { name: "verifyingContract", type: "address" },
        ],
        Application: [{ name: "value", type: "bytes32" }],
      },
      primaryType: "Application",
      domain: { name: "Application", version: "1", verifyingContract: request.signer.account },
      message: {
        value: `0x${"ab".repeat(32)}`,
      },
    };
    rehash(request);
    expectInvalid(request);
  });

  it("rejects every purpose, domain, signer, replay, digest, and package contradiction", () => {
    const variants: GoldenKernelEnableRequest[] = [];

    const wrongPurpose = clone(GOLDEN);
    (wrongPurpose as { purpose: string }).purpose = "application";
    variants.push(wrongPurpose);

    const wrongSigner = clone(GOLDEN);
    (wrongSigner.signer as { account: `0x${string}` }).account =
      "0x2222222222222222222222222222222222222222";
    variants.push(wrongSigner);

    const wrongDomain = clone(GOLDEN);
    (wrongDomain.typedData.domain as { name: string }).name = "Not Kernel";
    rehash(wrongDomain);
    variants.push(wrongDomain);

    const chainBound = clone(GOLDEN);
    (
      chainBound.typedData.types as unknown as Record<string, readonly Record<string, string>[]>
    ).EIP712Domain = [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ];
    (chainBound.typedData.domain as { chainId: string }).chainId = "1";
    rehash(chainBound);
    variants.push(chainBound);

    const wrongReplayNonce = clone(GOLDEN);
    (wrongReplayNonce.replay as { nonce: string }).nonce = "1";
    variants.push(wrongReplayNonce);

    const deadline = clone(GOLDEN);
    (deadline.replay as { deadline: string }).deadline = "1";
    variants.push(deadline);

    const wrongDigest = clone(GOLDEN);
    (wrongDigest as { expectedDigest: `0x${string}` }).expectedDigest = `0x${"00".repeat(32)}`;
    variants.push(wrongDigest);

    const noPackages = clone(GOLDEN);
    (noPackages.typedData.message as unknown as { packages: readonly never[] }).packages = [];
    rehash(noPackages);
    variants.push(noPackages);

    const unsupportedModuleType = clone(GOLDEN);
    const first = unsupportedModuleType.typedData.message.packages[0];
    if (!first) throw new Error("missing golden Kernel package");
    (first as { moduleType: string }).moduleType = "7";
    rehash(unsupportedModuleType);
    variants.push(unsupportedModuleType);

    for (const variant of variants) expectInvalid(variant);
  });

  it("captures builder input exactly and bounds the package list", () => {
    const input = {
      account: GOLDEN.signer.account,
      nonce: GOLDEN.typedData.message.nonce,
      packages: numericPackages(),
    };
    const hostile = Object.defineProperty({ ...input }, "account", {
      enumerable: true,
      get: () => {
        throw new Error("hostile getter");
      },
    });
    const oversized = {
      ...input,
      packages: Array.from({ length: 257 }, () => clone(input.packages[0])),
    };
    const oversizedBytes = {
      ...input,
      packages: input.packages.map((install, index) =>
        index === 0 ? { ...install, moduleData: `0x${"00".repeat(16 * 1024 + 1)}` } : install,
      ),
    };
    for (const value of [{ ...input, extra: true }, hostile, oversized, oversizedBytes]) {
      expect(() => createKernelV4ReplayableInstallTypedData(value as never)).toThrowError(
        expect.objectContaining({ code: "signing_request_invalid" }),
      );
    }
  });

  it("owns the current permission package sequence and normalized install snapshot", () => {
    const packages = numericPackages();
    const captured = parseKernelV4InstallPackages(packages);
    expect(captured).toEqual(packages);
    expect(Object.isFrozen(captured)).toBe(true);
    expect(captured.every((install) => Object.isFrozen(install))).toBe(true);

    expect(() => parseKernelV4InstallPackages(packages.slice(1))).toThrowError(
      expect.objectContaining({ code: "signing_request_invalid" }),
    );
  });
});
