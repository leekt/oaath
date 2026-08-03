import { ECDSA_SIGNER_CONTRACT } from "@zerodev/permissions";
import { toECDSASigner, toSignerId } from "@zerodev/permissions/signers";
import { encodeAbiParameters, recoverMessageAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import {
  createEcdsaPermissionSignerRuntime,
  type EcdsaPermissionSignerCapability,
  type EcdsaPermissionSignerErrorCode,
  OgpEcdsaPermissionSignerError,
} from "../src/index.js";

const profileVersion = "ogp.operator-credential-profile/v1" as const;
const hash = `0x${"ab".repeat(32)}` as const;

function profile(address: `0x${string}`) {
  return {
    version: profileVersion,
    kind: "ecdsa" as const,
    address,
  };
}

function fixture() {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const address = account.address.toLowerCase() as `0x${string}`;
  const calls: Readonly<{ hash: `0x${string}` }>[] = [];
  const capability: EcdsaPermissionSignerCapability = {
    address,
    async signMessageHash(request) {
      calls.push(request);
      return account.signMessage({ message: { raw: request.hash } });
    },
  };
  return { account, address, calls, capability, privateKey };
}

async function expectCode(
  operation: () => Promise<unknown>,
  code: EcdsaPermissionSignerErrorCode,
): Promise<OgpEcdsaPermissionSignerError> {
  let caught: unknown;
  try {
    await operation();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(OgpEcdsaPermissionSignerError);
  expect(caught).toMatchObject({ code });
  return caught as OgpEcdsaPermissionSignerError;
}

function collectKeys(value: unknown, keys = new Set<string>()): Set<string> {
  if (!value || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value)) {
    keys.add(key.toLowerCase());
    collectKeys(child, keys);
  }
  return keys;
}

describe("ECDSA permission signer", () => {
  it("owns the exact chain-neutral ZeroDev signer identity", async () => {
    const operator = fixture();
    const runtime = await createEcdsaPermissionSignerRuntime({
      profile: profile(operator.address),
      signer: operator.capability,
    });
    const recreated = await createEcdsaPermissionSignerRuntime({
      profile: profile(operator.address),
      signer: operator.capability,
    });
    const expectedSignerId =
      "0x0000000000000000000000000000000000000000000000000000000000000020" +
      "0000000000000000000000000000000000000000000000000000000000000028" +
      "6a6f069e2a08c2468e7724ab3250cdbfba14d4ff" +
      operator.address.slice(2) +
      "000000000000000000000000000000000000000000000000";

    expect(ECDSA_SIGNER_CONTRACT).toBe("0x6A6F069E2a08c2468e7724Ab3250CdBFBA14D4FF");
    expect(runtime).toMatchObject({
      profile: profile(operator.address),
      signerContractAddress: "0x6a6f069e2a08c2468e7724ab3250cdbfba14d4ff",
      signerData: operator.address,
      signerId: expectedSignerId,
    });
    expect(runtime.signerId).toHaveLength(2 + 128 * 2);
    expect(runtime.dummySignature).toMatch(/^0x[0-9a-f]{130}$/u);
    expect(recreated.signerContractAddress).toBe(runtime.signerContractAddress);
    expect(recreated.signerData).toBe(runtime.signerData);
    expect(recreated.signerId).toBe(runtime.signerId);
    expect(recreated.dummySignature).toBe(runtime.dummySignature);
    expect(Object.isFrozen(runtime)).toBe(true);
    expect(Object.isFrozen(runtime.profile)).toBe(true);

    const forbidden = new Set([
      "account",
      "chain",
      "chainid",
      "chains",
      "default",
      "fallback",
      "permissionid",
      "policies",
      "policy",
    ]);
    for (const key of collectKeys(runtime)) expect(forbidden.has(key)).toBe(false);
    expect(Object.keys(runtime).sort()).toEqual([
      "dummySignature",
      "profile",
      "signMessageHash",
      "signerContractAddress",
      "signerData",
      "signerId",
    ]);
  });

  it("matches the public upstream adapter and signer-ID codec", async () => {
    const operator = fixture();
    const upstream = await toECDSASigner({ signer: privateKeyToAccount(operator.privateKey) });
    const runtime = await createEcdsaPermissionSignerRuntime({
      profile: profile(operator.address),
      signer: operator.capability,
    });

    expect(upstream.account.address.toLowerCase()).toBe(operator.address);
    expect(upstream.signerContractAddress.toLowerCase()).toBe(runtime.signerContractAddress);
    expect(upstream.getSignerData().toLowerCase()).toBe(runtime.signerData);
    expect(toSignerId(upstream).toLowerCase()).toBe(runtime.signerId);
    expect(upstream.getDummySignature().toLowerCase()).toBe(runtime.dummySignature);
    expect(runtime.signerId).toBe(
      encodeAbiParameters(
        [{ name: "signerData", type: "bytes" }],
        [`${runtime.signerContractAddress}${operator.address.slice(2)}`],
      ),
    );
  });

  it("signs one exact hash, freezes the callback request, and normalizes v", async () => {
    const operator = fixture();
    const callback = vi.fn(async (request: Readonly<{ hash: `0x${string}` }>) => {
      expect(Object.isFrozen(request)).toBe(true);
      const signature = await operator.account.signMessage({ message: { raw: request.hash } });
      const v = signature.endsWith("1b") ? "00" : "01";
      return `${signature.slice(0, -2)}${v}`;
    });
    const runtime = await createEcdsaPermissionSignerRuntime({
      profile: profile(operator.address),
      signer: { address: operator.address, signMessageHash: callback },
    });

    const signature = await runtime.signMessageHash({ hash });
    expect(callback).toHaveBeenCalledTimes(1);
    expect(callback).toHaveBeenCalledWith({ hash });
    expect(signature).toMatch(/^0x[0-9a-f]{128}(?:1b|1c)$/u);
    expect((await recoverMessageAddress({ message: { raw: hash }, signature })).toLowerCase()).toBe(
      operator.address,
    );
  });

  it("captures the profile and capability once before later mutation", async () => {
    const operator = fixture();
    const other = fixture();
    const mutableProfile = profile(operator.address);
    const mutableCapability = { ...operator.capability };
    const runtime = await createEcdsaPermissionSignerRuntime({
      profile: mutableProfile,
      signer: mutableCapability,
    });
    mutableProfile.address = other.address;
    mutableCapability.address = other.address;
    mutableCapability.signMessageHash = other.capability.signMessageHash;

    const signature = await runtime.signMessageHash({ hash });
    expect(runtime.profile.address).toBe(operator.address);
    expect((await recoverMessageAddress({ message: { raw: hash }, signature })).toLowerCase()).toBe(
      operator.address,
    );
    expect(operator.calls).toHaveLength(1);
    expect(other.calls).toHaveLength(0);
  });

  it("rejects wrong profile authority, mismatches, aliases, and hostile objects", async () => {
    const operator = fixture();
    const other = fixture();
    const alias = profile(operator.address);
    const ownerProfile = {
      version: "ogp.owner-credential-profile/v1",
      kind: "ecdsa",
      address: operator.address,
    };
    const webAuthnProfile = {
      version: profileVersion,
      kind: "webauthn",
      publicKey:
        "0x04f9e11747ad8206db294686a72a031f8a30b9b7ac2585c4d571a84dfdbab6f4a4ebe3f069ca98aa8237373321d0962719899075e1cd2a09a30863254f0e5c32d8",
      authenticatorIdHash: `0x${"22".repeat(32)}`,
    };
    for (const badProfile of [
      ownerProfile,
      webAuthnProfile,
      { ...profile(operator.address), address: operator.address.toUpperCase() },
      { ...profile(operator.address), address: `0x${"00".repeat(20)}` },
      { ...profile(operator.address), extra: true },
    ]) {
      await expectCode(
        () =>
          createEcdsaPermissionSignerRuntime({
            profile: badProfile,
            signer: operator.capability,
          }),
        "ecdsa_permission_signer_input_invalid",
      );
    }
    await expectCode(
      () =>
        createEcdsaPermissionSignerRuntime({
          profile: profile(operator.address),
          signer: other.capability,
        }),
      "ecdsa_permission_signer_binding_mismatch",
    );
    await expectCode(
      () => createEcdsaPermissionSignerRuntime({ profile: alias, signer: alias }),
      "ecdsa_permission_signer_capability_invalid",
    );

    const accessor = Object.defineProperty({}, "address", {
      enumerable: true,
      get: () => operator.address,
    });
    Object.defineProperty(accessor, "signMessageHash", {
      enumerable: true,
      value: operator.capability.signMessageHash,
    });
    for (const signer of [
      accessor,
      { ...operator.capability, extra: true },
      Object.assign(Object.create({ inherited: true }), operator.capability),
      Object.assign({ ...operator.capability }, { [Symbol("hidden")]: true }),
      new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error("capability secret");
          },
        },
      ),
    ]) {
      const error = await expectCode(
        () =>
          createEcdsaPermissionSignerRuntime({
            profile: profile(operator.address),
            signer,
          }),
        "ecdsa_permission_signer_capability_invalid",
      );
      expect(error.message).not.toContain("secret");
    }
  });

  it("rejects malformed requests before signing", async () => {
    const operator = fixture();
    const callback = vi.fn(operator.capability.signMessageHash);
    const runtime = await createEcdsaPermissionSignerRuntime({
      profile: profile(operator.address),
      signer: { address: operator.address, signMessageHash: callback },
    });
    for (const request of [
      null,
      hash,
      { raw: hash },
      { hash: "0x" },
      { hash: hash.toUpperCase() },
      { hash, extra: true },
      Object.assign({ hash }, { [Symbol("hidden")]: true }),
      Object.defineProperty({}, "hash", { enumerable: true, get: () => hash }),
      new Proxy(
        {},
        {
          ownKeys() {
            throw new Error("request secret");
          },
        },
      ),
    ]) {
      const error = await expectCode(
        () => runtime.signMessageHash(request),
        "ecdsa_permission_signer_request_invalid",
      );
      expect(error.message).not.toContain("secret");
    }
    expect(callback).not.toHaveBeenCalled();
  });

  it("rejects malformed, unsupported-v, wrong-key, and failed signer results", async () => {
    const operator = fixture();
    const other = fixture();
    const valid = await operator.account.signMessage({ message: { raw: hash } });
    const failures: Array<() => Promise<unknown>> = [
      async () => undefined,
      async () => "0x",
      async () => valid.toUpperCase(),
      async () => `${valid.slice(0, -2)}02`,
      async () => other.account.signMessage({ message: { raw: hash } }),
      async () => {
        throw new Error("provider secret");
      },
    ];
    for (const signMessageHash of failures) {
      const runtime = await createEcdsaPermissionSignerRuntime({
        profile: profile(operator.address),
        signer: { address: operator.address, signMessageHash },
      });
      const error = await expectCode(
        () => runtime.signMessageHash({ hash }),
        "ecdsa_permission_signer_signing_failed",
      );
      expect(error.message).not.toContain("provider secret");
    }
  });
});
