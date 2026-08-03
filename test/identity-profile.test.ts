import { describe, expect, it, vi } from "vitest";
import {
  createKernelAccountActionInput,
  diagnoseOperatorCredential,
  diagnoseOwnerCredential,
  type KernelAccountProfile,
  OGP_KERNEL_ACCOUNT_PROFILE_VERSION,
  OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OGP_OWNER_CREDENTIAL_PROFILE_VERSION,
  OgpIdentityProfileError,
  type OperatorCredentialProfile,
  type OwnerCredentialProfile,
  parseKernelAccountProfile,
  parseOperatorCredentialProfile,
  parseOwnerCredentialProfile,
} from "../src/index.js";

const p256PublicKey =
  "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" as const;

const ownerEcdsa: OwnerCredentialProfile = {
  version: "ogp.owner-credential-profile/v1",
  kind: "ecdsa",
  address: `0x${"11".repeat(20)}`,
};

const ownerP256: OwnerCredentialProfile = {
  version: "ogp.owner-credential-profile/v1",
  kind: "p256",
  publicKey: p256PublicKey,
};

const ownerWebAuthn: OwnerCredentialProfile = {
  version: "ogp.owner-credential-profile/v1",
  kind: "webauthn",
  publicKey: p256PublicKey,
  authenticatorIdHash: `0x${"22".repeat(32)}`,
};

const operatorEcdsa: OperatorCredentialProfile = {
  version: "ogp.operator-credential-profile/v1",
  kind: "ecdsa",
  address: `0x${"33".repeat(20)}`,
};

const operatorWebAuthn: OperatorCredentialProfile = {
  version: "ogp.operator-credential-profile/v1",
  kind: "webauthn",
  publicKey: p256PublicKey,
  authenticatorIdHash: `0x${"44".repeat(32)}`,
};

const accountProfile: KernelAccountProfile = {
  version: "ogp.kernel-account-profile/v1",
  kind: "kernel",
  accountIndex: "7",
  kernelVersion: "0.3.3",
  factoryRoute: "meta_factory",
  entryPoint: { version: "0.7" },
  ownerCredential: ownerP256,
};

function clone<Value>(value: Value): Value {
  return JSON.parse(JSON.stringify(value)) as Value;
}

function expectProfileError(action: () => unknown, code: OgpIdentityProfileError["code"]): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(OgpIdentityProfileError);
    expect(error).toMatchObject({ code });
    return;
  }
  throw new Error(`Expected ${code}`);
}

function collectKeys(value: unknown, keys = new Set<string>()): Set<string> {
  if (value === null || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value)) {
    keys.add(key.toLowerCase());
    collectKeys(child, keys);
  }
  return keys;
}

describe("identity profile codecs", () => {
  it("round-trips the three exact owner public-identity shapes immutably", () => {
    expect(OGP_OWNER_CREDENTIAL_PROFILE_VERSION).toBe("ogp.owner-credential-profile/v1");
    for (const profile of [ownerEcdsa, ownerP256, ownerWebAuthn]) {
      const mutable = clone(profile) as unknown as Record<string, unknown>;
      const parsed = parseOwnerCredentialProfile(mutable);
      mutable.kind = "changed";
      expect(parsed).toEqual(profile);
      expect(Object.isFrozen(parsed)).toBe(true);
      expect(parseOwnerCredentialProfile(clone(parsed))).toEqual(parsed);
    }

    expect(parseOwnerCredentialProfile(ownerP256)).not.toEqual(
      parseOwnerCredentialProfile(ownerWebAuthn),
    );
    expect(parseOwnerCredentialProfile(ownerWebAuthn)).not.toEqual(
      parseOwnerCredentialProfile({
        ...ownerWebAuthn,
        authenticatorIdHash: `0x${"55".repeat(32)}`,
      }),
    );
  });

  it("accepts only the first-party ECDSA and WebAuthn operator shapes", () => {
    expect(OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION).toBe("ogp.operator-credential-profile/v1");
    expect(parseOperatorCredentialProfile(operatorEcdsa)).toEqual(operatorEcdsa);
    expect(parseOperatorCredentialProfile(operatorWebAuthn)).toEqual(operatorWebAuthn);
    expectProfileError(
      () =>
        parseOperatorCredentialProfile({
          version: "ogp.operator-credential-profile/v1",
          kind: "p256",
          publicKey: p256PublicKey,
        }),
      "operator_credential_profile_invalid",
    );
  });

  it("rejects malformed or non-curve P-256 identities", () => {
    for (const publicKey of [
      `0x02${p256PublicKey.slice(4, 68)}`,
      p256PublicKey.toUpperCase(),
      `0x04${"00".repeat(64)}`,
      `${p256PublicKey.slice(0, -1)}4`,
    ]) {
      expectProfileError(
        () =>
          parseOwnerCredentialProfile({
            version: "ogp.owner-credential-profile/v1",
            kind: "p256",
            publicKey,
          }),
        "owner_credential_profile_invalid",
      );
    }
  });

  it("owns one exact Kernel profile and binds one caller-supplied action chain", () => {
    expect(OGP_KERNEL_ACCOUNT_PROFILE_VERSION).toBe("ogp.kernel-account-profile/v1");
    const parsed = parseKernelAccountProfile(clone(accountProfile));
    expect(parsed).toEqual(accountProfile);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.entryPoint)).toBe(true);
    expect(Object.isFrozen(parsed.ownerCredential)).toBe(true);

    const first = createKernelAccountActionInput(parsed, 1);
    const later = createKernelAccountActionInput(parsed, 137);
    expect(first).toEqual({
      chainId: 1,
      accountIndex: "7",
      kernelVersion: "0.3.3",
      factoryRoute: "meta_factory",
      entryPointVersion: "0.7",
      ownerCredential: ownerP256,
    });
    expect(later).toEqual({ ...first, chainId: 137 });
    expect(Object.isFrozen(first)).toBe(true);
    expect(first.ownerCredential).toEqual(parsed.ownerCredential);
    expect(first.ownerCredential).not.toBe(parsed.ownerCredential);
    expect(Object.isFrozen(first.ownerCredential)).toBe(true);

    const profileKeys = collectKeys(parsed);
    for (const forbidden of [
      "chainid",
      "chainids",
      "chains",
      "supportedchains",
      "account",
      "default",
      "fallback",
    ]) {
      expect(profileKeys.has(forbidden), `forbidden profile key: ${forbidden}`).toBe(false);
    }
  });

  it("diagnoses only the selected exact credential kind from the pinned runtime", () => {
    expect(diagnoseOwnerCredential(ownerEcdsa)).toEqual({
      status: "available",
      capability: "owner_ecdsa",
      profile: ownerEcdsa,
    });
    expect(diagnoseOwnerCredential(ownerWebAuthn)).toEqual({
      status: "absent",
      capability: "owner_webauthn",
      profile: ownerWebAuthn,
      reason: "required_package_not_installed",
    });
    expect(diagnoseOwnerCredential(ownerP256)).toEqual({
      status: "unsupported",
      capability: "owner_p256",
      profile: ownerP256,
      reason: "first_party_profile_unproven",
    });
    expect(diagnoseOperatorCredential(operatorEcdsa)).toMatchObject({
      status: "absent",
      capability: "permission_signer_ecdsa",
      profile: operatorEcdsa,
    });
    expect(diagnoseOperatorCredential(operatorWebAuthn)).toMatchObject({
      status: "absent",
      capability: "permission_signer_webauthn",
      profile: operatorWebAuthn,
    });
    expect(Object.isFrozen(diagnoseOwnerCredential(ownerP256))).toBe(true);
  });

  it("rejects versions, contradictory fields, extras, symbols, and accessors", () => {
    for (const value of [
      { ...ownerEcdsa, version: "ogp.owner-credential-profile/v0" },
      { version: "ogp.owner-credential-profile/v1", kind: "ecdsa" },
      { ...ownerEcdsa, address: `0x${"00".repeat(20)}` },
      { ...ownerEcdsa, publicKey: p256PublicKey },
      { ...ownerP256, address: ownerEcdsa.address },
      { ...ownerWebAuthn, authenticatorIdHash: "0x" },
      { ...ownerWebAuthn, [Symbol("hidden")]: true },
    ]) {
      expectProfileError(
        () => parseOwnerCredentialProfile(value),
        "owner_credential_profile_invalid",
      );
    }

    for (const replacement of [{ version: "0.6" }, { version: "0.7", extra: true }]) {
      expectProfileError(
        () => parseKernelAccountProfile({ ...accountProfile, entryPoint: replacement }),
        "kernel_account_profile_invalid",
      );
    }

    for (const replacement of [
      { ...accountProfile, version: "ogp.kernel-account-profile/v0" },
      { ...accountProfile, accountIndex: "01" },
      { ...accountProfile, kernelVersion: "0.3.4" },
      { ...accountProfile, factoryRoute: "other_factory" },
      { ...accountProfile, chainId: 1 },
    ]) {
      expectProfileError(
        () => parseKernelAccountProfile(replacement),
        "kernel_account_profile_invalid",
      );
    }

    const getter = vi.fn(() => "ecdsa");
    const accessor = { ...ownerEcdsa } as Record<string, unknown>;
    Object.defineProperty(accessor, "kind", { enumerable: true, get: getter });
    expectProfileError(
      () => parseOwnerCredentialProfile(accessor),
      "owner_credential_profile_invalid",
    );
    expect(getter).not.toHaveBeenCalled();
  });

  it("sanitizes hostile reflection failures and rejects invalid action chains", () => {
    const secret = "do-not-leak-profile-secret";
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error(secret);
        },
      },
    );
    try {
      parseOwnerCredentialProfile(hostile);
    } catch (error) {
      expect(error).toBeInstanceOf(OgpIdentityProfileError);
      expect(error).toMatchObject({ code: "owner_credential_profile_invalid" });
      expect((error as Error).message).not.toContain(secret);
    }

    for (const chainId of [undefined, null, 0, -0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expectProfileError(
        () => createKernelAccountActionInput(accountProfile, chainId),
        "kernel_account_action_input_invalid",
      );
    }
  });
});
