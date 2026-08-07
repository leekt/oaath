import { p256 } from "@noble/curves/nist.js";
import { OAATH_OWNER_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import {
  bytesToHex,
  concat,
  decodeAbiParameters,
  encodeAbiParameters,
  getAddress,
  hexToBytes,
  keccak256,
  pad,
  recoverAddress,
  sha256,
  stringToBytes,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
// Internal on purpose: a consumer reads this fact through
// diagnoseKernelCapability, so the pinned validator stays off the public surface.
import { pinnedValidatorModule } from "../src/kernel/modules.js";
import {
  compileKernelPermissionPolicy,
  createKernelRuntime,
  ecdsaKey,
  encodeKernelV4PermissionSignature,
  encodeKernelV4PolicyData,
  encodeKernelV4SignerData,
  encodeKernelV4ValidatorData,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_EXECUTE_SELECTOR,
  KERNEL_V4_EXECUTE_USER_OP_SELECTOR,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type KernelBuiltInKeyKind,
  type KernelKeyKind,
  type KernelOperatorAuthority,
  type KernelV4AccountReadRequest,
  type KeyProfile,
  kernelV4Deployment,
  type OperatorProfile,
  ownerOperator,
  p256Key,
  pinnedPolicyModule,
  pinnedSignerModule,
  sessionOperator,
  webauthnKey,
} from "../src/kernel.js";

const chainId = 421_614;
const deployment = kernelV4Deployment(chainId);
const validator = `0x${"22".repeat(20)}` as const;
const account = `0x${"66".repeat(20)}` as const;
const target = `0x${"44".repeat(20)}` as const;
const gas = Object.freeze({
  callGasLimit: "100000",
  verificationGasLimit: "200000",
  preVerificationGas: "30000",
  maxFeePerGas: "4",
  maxPriorityFeePerGas: "2",
});

const ecdsaAccount = privateKeyToAccount(`0x${"11".repeat(32)}`);
const p256PrivateKey = hexToBytes(`0x${"23".repeat(32)}`);
const p256PublicKey = bytesToHex(p256.getPublicKey(p256PrivateKey, false));
const rpId = "app.example";
const origin = "https://app.example";
const credentialId = "AAECAwQFBgcICQoLDA0ODw";
const authenticatorIdHash = keccak256(bytesToHex(base64UrlBytes(credentialId)));

const p256Credential = Object.freeze({
  version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  kind: "p256" as const,
  publicKey: p256PublicKey,
});
const webauthnCredential = Object.freeze({
  version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  kind: "webauthn" as const,
  publicKey: p256PublicKey,
  authenticatorIdHash,
});

function base64UrlBytes(value: string): Uint8Array {
  const padded = value
    .replace(/-/gu, "+")
    .replace(/_/gu, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function runtimeCodeHash(address: `0x${string}`): `0x${string}` {
  if (address === KERNEL_V4_ENTRY_POINT_V07) return KERNEL_V4_ENTRY_POINT_V07_CODE_HASH;
  if (address === KERNEL_V4_UUPS_IMPLEMENTATION_V07) {
    return deployment.implementationDeployment.runtimeCodeHash;
  }
  return KERNEL_V4_FACTORY_V07_CODE_HASH;
}

/**
 * The account read capability. `codeless` names one address observed to carry no
 * code, which is how a caller-bound module that was never deployed is proven
 * absent on the action chain.
 */
function reads(state: "counterfactual" | "deployed" = "counterfactual", codeless?: `0x${string}`) {
  return {
    async read(request: KernelV4AccountReadRequest): Promise<unknown> {
      if (request.type === "chain_id") return request.chainId;
      if (request.type === "runtime_code_hash") return runtimeCodeHash(request.address);
      if (request.type === "code") {
        if (request.address === codeless) return "0x";
        return request.address === account && state === "counterfactual" ? "0x" : "0x01";
      }
      if (request.type === "kernel_factory_implementation") {
        return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
      }
      if (request.type === "kernel_factory_account") return account;
      return KERNEL_V4_UUPS_IMPLEMENTATION_V07;
    },
  };
}

/** Signs a 32-byte hash with the raw P-256 test key, returning compact (r || s). */
function p256Sign(request: { readonly hash: `0x${string}` }): Promise<string> {
  const signature = p256.sign(hexToBytes(request.hash), p256PrivateKey, {
    lowS: true,
    prehash: false,
  });
  return Promise.resolve(`0x${signature.toCompactHex()}`);
}

interface AssertionOverrides {
  readonly type?: string;
  readonly origin?: string;
  readonly challenge?: string;
  readonly flags?: number;
  readonly highS?: boolean;
  readonly rpIdHash?: `0x${string}`;
}

function webauthnAuthenticate(overrides: AssertionOverrides = {}) {
  return async (request: {
    readonly hash: `0x${string}`;
    readonly challenge: string;
  }): Promise<unknown> => {
    const clientDataJSON = JSON.stringify({
      type: overrides.type ?? "webauthn.get",
      challenge: overrides.challenge ?? request.challenge,
      origin: overrides.origin ?? origin,
      crossOrigin: false,
    });
    const authenticatorData = concat([
      overrides.rpIdHash ?? sha256(stringToBytes(rpId)),
      toHex(overrides.flags ?? 0x05, { size: 1 }),
      "0x00000001",
    ]);
    const message = sha256(concat([authenticatorData, sha256(stringToBytes(clientDataJSON))]));
    const signature = p256.sign(hexToBytes(message), p256PrivateKey, {
      lowS: !overrides.highS,
      prehash: false,
    });
    const order = p256.CURVE.n;
    const s = overrides.highS && signature.s <= order / 2n ? order - signature.s : signature.s;
    return Object.freeze({
      authenticatorData,
      clientDataJSON,
      responseTypeLocation: String(Math.max(clientDataJSON.indexOf('"type":"webauthn.get"'), 0)),
      r: toHex(signature.r, { size: 32 }),
      s: toHex(s, { size: 32 }),
    });
  };
}

/** One consumer-authored kind and the permission signer module it binds itself. */
const customKind = "custom:demo" as const;
const customSigner = `0x${"33".repeat(20)}` as const;

/**
 * A consumer-authored KeyProfile: a credential kind this SDK does not author,
 * carrying its own validator and permission signer module. It wraps the ECDSA
 * machinery so the composition under test is the caller-bound path, never the
 * pinned registry — pinnedSignerModule(customKind) is null on every chain.
 */
function customKey(
  overrides: Readonly<{
    kind?: string;
    signerModule?: `0x${string}` | null;
    sign?: KeyProfile["sign"];
  }> = {},
): Readonly<KeyProfile> {
  const inner = ecdsaKey({ account: ecdsaAccount, validator });
  return Object.freeze({
    kind: (overrides.kind ?? customKind) as KernelKeyKind,
    publicMaterial: inner.publicMaterial,
    resolveValidator: inner.resolveValidator,
    signerModule: overrides.signerModule === undefined ? customSigner : overrides.signerModule,
    dummySignature: inner.dummySignature,
    sign: overrides.sign ?? inner.sign,
    verify: inner.verify,
  });
}

type MatrixKeyKind = KernelBuiltInKeyKind | typeof customKind;

const keyProfiles: Readonly<Record<MatrixKeyKind, () => Readonly<KeyProfile>>> = Object.freeze({
  ecdsa: () => ecdsaKey({ account: ecdsaAccount, validator }),
  p256: () => p256Key({ credential: p256Credential, sign: p256Sign }),
  webauthn: () =>
    webauthnKey({
      credential: webauthnCredential,
      credentialId,
      rpId,
      origin,
      authenticate: webauthnAuthenticate(),
    }),
  [customKind]: () => customKey(),
});

/** One bounded scope every session composition in this file installs. */
const sessionScope = Object.freeze({
  kind: "call" as const,
  permissions: Object.freeze([
    Object.freeze({ target, selector: KERNEL_V4_EXECUTE_SELECTOR, valueLimit: "0" }),
  ]),
});

const operatorProfiles: Readonly<
  Record<KernelOperatorAuthority, (key: Readonly<KeyProfile>) => Readonly<OperatorProfile>>
> = Object.freeze({
  owner: (key) => ownerOperator({ key }),
  session: (key) => sessionOperator({ key, policies: [sessionScope] }),
});

function ecdsaRuntime(authority: KernelOperatorAuthority, state?: "counterfactual" | "deployed") {
  return createKernelRuntime({
    deployment,
    operator: operatorProfiles[authority](keyProfiles.ecdsa()),
    reads: reads(state),
  });
}

async function ecdsaAccountDescriptor() {
  const runtime = ecdsaRuntime("owner");
  return runtime.bindAccount({ accountIndex: "0", initialPackages: runtime.packages });
}

describe("Kernel composition matrix", () => {
  const matrix: readonly (readonly [MatrixKeyKind, KernelOperatorAuthority])[] = [
    ["ecdsa", "owner"],
    ["ecdsa", "session"],
    ["p256", "owner"],
    ["p256", "session"],
    ["webauthn", "owner"],
    ["webauthn", "session"],
    // The same factory, the same two authorities, a kind this SDK never authored.
    [customKind, "owner"],
    [customKind, "session"],
  ];

  it.each(matrix)(
    "composes the %s key with %s authority through one factory",
    (kind, authority) => {
      const key = keyProfiles[kind]();
      expect(key.kind).toBe(kind);
      const composeOperator = () => operatorProfiles[authority](key);
      // An owner needs a validator module for its key kind and a session needs a
      // permission signer module: raw P-256 has only the validator, WebAuthn only
      // the signer, so each axis fails closed on its own module rather than
      // borrowing the other's. A consumer-authored kind binds both itself.
      const callerBound = kind === "ecdsa" || kind === customKind;
      const unavailable =
        authority === "session"
          ? kind === "p256"
            ? "kernel_runtime_signer_unavailable"
            : null
          : callerBound || kind === "p256"
            ? null
            : "kernel_runtime_validator_unavailable";
      if (authority === "session" && unavailable) {
        expect(composeOperator).toThrowError(
          expect.objectContaining({ name: "OaathKernelRuntimeError", code: unavailable }),
        );
        return;
      }
      const operator = composeOperator();
      expect(operator).toMatchObject({ authority });
      expect(operator.key.kind).toBe(kind);
      const compose = () => createKernelRuntime({ deployment, operator, reads: reads() });
      if (unavailable) {
        expect(compose).toThrowError(
          expect.objectContaining({ name: "OaathKernelRuntimeError", code: unavailable }),
        );
        return;
      }

      const runtime = compose();
      expect(runtime).toMatchObject({ authority, keyKind: kind, deployment });
      if (authority === "owner") {
        // A caller-bound kind installs the validator its own profile named; raw
        // P-256 installs the pinned reviewed one, which is not that address.
        const authorityModule = kind === "p256" ? pinnedValidatorModule("p256") : validator;
        expect(kind === "p256" ? authorityModule !== validator : true).toBe(true);
        expect(operator.policy).toBeNull();
        expect(runtime.authorityModule).toBe(authorityModule);
        expect(runtime.validation).toEqual({ kind: "root" });
        expect(runtime.packages).toEqual([
          {
            moduleType: 1,
            module: authorityModule,
            moduleData: key.publicMaterial,
            internalData: encodeKernelV4ValidatorData({ hook: "none", selectors: [] }),
          },
        ]);
        return;
      }

      // A session installs a permission: the policy that bounds its calls, then
      // the signer that carries the key material, both under one permission ID.
      // A reviewed kind takes the pinned module; a consumer-authored kind takes
      // the one its own profile bound, and the registry pins nothing for it.
      const signer = kind === customKind ? customSigner : pinnedSignerModule(kind);
      if (kind === customKind) expect(pinnedSignerModule(kind)).toBeNull();
      expect(runtime.authorityModule).toBe(signer);
      const validation = runtime.validation;
      if (validation.kind !== "permission")
        throw new Error("session validation is not a permission");
      expect(validation.permissionId).toMatch(/^0x[0-9a-f]{8}$/u);
      const paddedId = pad(validation.permissionId, { size: 32, dir: "right" });
      expect(runtime.packages).toEqual([
        {
          moduleType: 5,
          module: pinnedPolicyModule("call"),
          moduleData: concat([
            paddedId,
            compileKernelPermissionPolicy([sessionScope]).packages[0]?.policyData ?? "0x",
          ]),
          internalData: encodeKernelV4PolicyData(validation.permissionId),
        },
        {
          moduleType: 6,
          module: signer,
          moduleData: concat([paddedId, key.publicMaterial]),
          internalData: encodeKernelV4SignerData({
            permissionId: validation.permissionId,
            hook: "none",
            selectors: [KERNEL_V4_EXECUTE_SELECTOR],
          }),
        },
      ]);
      expect(runtime.dummySignature).toBe(
        encodeKernelV4PermissionSignature([
          ...runtime.packages.filter(({ moduleType }) => moduleType === 5).map(() => "0x" as const),
          key.dummySignature,
        ]),
      );
    },
  );

  it.each(["owner", "session"] as const)(
    "prepares and signs %s operations with the composed key",
    async (authority) => {
      const runtime = ecdsaRuntime(authority);
      const descriptor = await ecdsaAccountDescriptor();
      const prepared = runtime.prepareOperation({
        kind: "execution",
        grantId: "kernel-composition",
        account: descriptor,
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "1", data: "0x" }],
        gas,
      });
      // Root and permission validations both carry plain execute calldata: root is
      // exempt from the selector allow-list and a hookless permission takes
      // Kernel's fast path, which the policy module's decoder requires.
      expect(prepared.userOperation.callData.startsWith(KERNEL_V4_EXECUTE_USER_OP_SELECTOR)).toBe(
        false,
      );
      expect(prepared.chainId).toBe(chainId);
      expect(prepared.userOperation.paymaster).toBeNull();

      // The runtime threads an optional paymaster into the hashed identity.
      const paymaster = Object.freeze({
        address: `0x${"77".repeat(20)}` as const,
        verificationGasLimit: "60000",
        postOpGasLimit: "25000",
        data: "0x" as const,
      });
      const sponsored = runtime.prepareOperation({
        kind: "execution",
        grantId: "kernel-composition",
        account: descriptor,
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "1", data: "0x" }],
        gas,
        paymaster,
      });
      expect(sponsored.userOperation.paymaster).toEqual(paymaster);
      expect(sponsored.userOperationHash).not.toBe(prepared.userOperationHash);

      const signature = await runtime.signOperation(prepared);
      if (authority === "owner") {
        expect(await recoverAddress({ hash: prepared.userOperationHash, signature })).toBe(
          getAddress(ecdsaAccount.address),
        );
        return;
      }
      // A session signs inside Kernel's permission envelope: one empty slice for
      // the policy, which reads no signature, then the signer slice last.
      const [slices] = decodeAbiParameters([{ name: "signatures", type: "bytes[]" }], signature);
      const signerSlice = slices[1];
      if (!signerSlice) throw new Error("permission envelope carries no signer slice");
      expect(slices.length).toBe(2);
      expect(slices[0]).toBe("0x");
      expect(
        await recoverAddress({ hash: prepared.userOperationHash, signature: signerSlice }),
      ).toBe(getAddress(ecdsaAccount.address));
    },
  );

  it.each([1, 2, 3] as const)(
    "envelopes one empty policy slice per installed package for %i policy packages",
    async (packageCount) => {
      // Kernel's _validateUserOpPermission requires
      // signatures.length == policies.length + 1 and reverts InvalidSignature
      // otherwise, so the envelope's slice count is read back from the packages the
      // permission actually installs rather than from a literal in the test.
      const policies = [
        sessionScope,
        { kind: "expiry" as const, validAfter: "0", validUntil: "1750000000" },
        { kind: "operation-limit" as const, maximumOperations: "5" },
      ].slice(0, packageCount);
      const runtime = createKernelRuntime({
        deployment,
        operator: sessionOperator({ key: keyProfiles.ecdsa(), policies }),
        reads: reads(),
      });
      const installedPolicies = runtime.packages.filter((entry) => entry.moduleType === 5);
      expect(installedPolicies).toHaveLength(packageCount);
      const prepared = runtime.prepareOperation({
        kind: "execution",
        grantId: "kernel-composition-slices",
        account: await ecdsaAccountDescriptor(),
        nonceKey: "0",
        sequence: "0",
        calls: [{ target, value: "1", data: "0x" }],
        gas,
      });
      const [slices] = decodeAbiParameters(
        [{ name: "signatures", type: "bytes[]" }],
        await runtime.signOperation(prepared),
      );
      expect(slices.length).toBe(installedPolicies.length + 1);
      expect(slices.slice(0, installedPolicies.length)).toEqual(installedPolicies.map(() => "0x"));
      const signerSlice = slices[installedPolicies.length];
      if (!signerSlice) throw new Error("permission envelope carries no signer slice");
      expect(
        await recoverAddress({ hash: prepared.userOperationHash, signature: signerSlice }),
      ).toBe(getAddress(ecdsaAccount.address));
    },
  );

  it("binds counterfactual and deployed accounts through the runtime", async () => {
    const runtime = ecdsaRuntime("owner");
    await expect(
      runtime.bindAccount({ accountIndex: "0", initialPackages: runtime.packages }),
    ).resolves.toMatchObject({ state: "counterfactual", account, chainId });
    const deployed = ecdsaRuntime("owner", "deployed");
    await expect(
      deployed.bindAccount({ accountIndex: "0", initialPackages: deployed.packages }),
    ).resolves.toMatchObject({ state: "deployed", account });
  });

  it("refuses to bind an account whose root packages exclude the owner authority", async () => {
    const runtime = ecdsaRuntime("owner");
    await expect(
      runtime.bindAccount({
        accountIndex: "0",
        initialPackages: [
          {
            moduleType: 1,
            module: `0x${"77".repeat(20)}`,
            moduleData: ecdsaAccount.address.toLowerCase() as `0x${string}`,
            internalData: encodeKernelV4ValidatorData({ hook: "none", selectors: [] }),
          },
        ],
      }),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });
  });

  it("accepts a session account bound to another authority's root packages", async () => {
    const owner = ecdsaRuntime("owner");
    const session = ecdsaRuntime("session");
    await expect(
      session.bindAccount({ accountIndex: "0", initialPackages: owner.packages }),
    ).resolves.toMatchObject({ account });
  });

  it("refuses to sign an operation prepared for another authority", async () => {
    const owner = ecdsaRuntime("owner");
    const session = ecdsaRuntime("session");
    const descriptor = await ecdsaAccountDescriptor();
    const operation = {
      kind: "execution" as const,
      grantId: "kernel-composition",
      account: descriptor,
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "1", data: "0x" as const }],
      gas,
    };
    await expect(owner.signOperation(session.prepareOperation(operation))).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
    await expect(session.signOperation(owner.prepareOperation(operation))).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
  });

  it("verifies and envelopes one external session signature for the exact operation", async () => {
    const runtime = ecdsaRuntime("session");
    const prepared = runtime.prepareOperation({
      kind: "execution",
      grantId: "kernel-external-signature",
      account: await ecdsaAccountDescriptor(),
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "1", data: "0x" }],
      gas,
    });
    const raw = await ecdsaAccount.sign({ hash: prepared.userOperationHash });
    const enveloped = await runtime.encodeVerifiedSignature(prepared, raw.toUpperCase());
    const [slices] = decodeAbiParameters([{ name: "signatures", type: "bytes[]" }], enveloped);
    const signerSlice = slices[1];
    if (!signerSlice) throw new Error("permission envelope carries no signer slice");
    expect(slices).toHaveLength(2);
    expect(slices[0]).toBe("0x");
    expect(await recoverAddress({ hash: prepared.userOperationHash, signature: signerSlice })).toBe(
      getAddress(ecdsaAccount.address),
    );

    const foreign = privateKeyToAccount(`0x${"12".repeat(32)}`);
    await expect(
      runtime.encodeVerifiedSignature(
        prepared,
        await foreign.sign({ hash: prepared.userOperationHash }),
      ),
    ).rejects.toMatchObject({ code: "kernel_runtime_signature_invalid" });
    await expect(runtime.encodeVerifiedSignature(prepared, "not-hex")).rejects.toMatchObject({
      code: "kernel_runtime_input_invalid",
    });
    await expect(
      ecdsaRuntime("owner").encodeVerifiedSignature(prepared, raw),
    ).rejects.toMatchObject({ code: "kernel_runtime_binding_mismatch" });
  });

  it("refuses to sign an operation prepared for another chain", async () => {
    const runtime = createKernelRuntime({
      deployment: kernelV4Deployment(11_155_111),
      operator: operatorProfiles.owner(keyProfiles.ecdsa()),
      reads: reads(),
    });
    const prepared = ecdsaRuntime("owner").prepareOperation({
      kind: "execution",
      grantId: "kernel-composition",
      account: await ecdsaAccountDescriptor(),
      nonceKey: "0",
      sequence: "0",
      calls: [{ target, value: "1", data: "0x" }],
      gas,
    });
    await expect(runtime.signOperation(prepared)).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
  });

  it("refuses to sign an unreadable prepared operation", async () => {
    await expect(ecdsaRuntime("owner").signOperation({ version: "other" })).rejects.toMatchObject({
      code: "kernel_runtime_binding_mismatch",
    });
  });

  it.each([
    [
      "unknown field",
      {
        deployment,
        operator: operatorProfiles.owner(keyProfiles.ecdsa()),
        reads: reads(),
        extra: 1,
      },
    ],
    [
      "copied deployment profile",
      {
        deployment: { ...deployment },
        operator: operatorProfiles.owner(keyProfiles.ecdsa()),
        reads: reads(),
      },
    ],
    [
      "missing read capability",
      { deployment, operator: operatorProfiles.owner(keyProfiles.ecdsa()), reads: { read: "0x" } },
    ],
    [
      "hostile operator",
      {
        deployment,
        operator: {
          authority: "owner",
          key: keyProfiles.ecdsa(),
          policy: null,
          resolveValidation: null,
          resolvePackages: null,
        },
        reads: reads(),
      },
    ],
  ] as const)("fails closed on %s", (_label, input) => {
    expect(() => createKernelRuntime(input as never)).toThrowError(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );
  });

  it("rejects an unsupported deployment chain", () => {
    expect(() =>
      createKernelRuntime({
        deployment: { chainId: 1 } as never,
        operator: operatorProfiles.owner(keyProfiles.ecdsa()),
        reads: reads(),
      }),
    ).toThrowError(expect.objectContaining({ code: "kernel_v4_chain_unsupported" }));
  });
});

describe("Consumer-authored key profiles", () => {
  const operation = Object.freeze({
    kind: "execution" as const,
    grantId: "kernel-composition-custom",
    nonceKey: "0",
    sequence: "0",
    calls: Object.freeze([Object.freeze({ target, value: "1", data: "0x" as const })]),
    gas,
  });

  function customRuntime(
    authority: KernelOperatorAuthority,
    key: Readonly<KeyProfile> = customKey(),
    codeless?: `0x${string}`,
  ) {
    return createKernelRuntime({
      deployment,
      operator: operatorProfiles[authority](key),
      reads: reads("counterfactual", codeless),
    });
  }

  it.each(["owner", "session"] as const)(
    "prepares and signs %s operations for a kind this SDK never authored",
    async (authority) => {
      const runtime = customRuntime(authority);
      expect(runtime.keyKind).toBe(customKind);
      const descriptor = await runtime.bindAccount({
        accountIndex: "0",
        // The account's root packages are the owner's, on every authority.
        initialPackages: customRuntime("owner").packages,
      });
      const prepared = runtime.prepareOperation({ ...operation, account: descriptor });
      const signature = await runtime.signOperation(prepared);
      if (authority === "owner") {
        // Root validation carries no envelope, so the signature is the key's own.
        expect(await recoverAddress({ hash: prepared.userOperationHash, signature })).toBe(
          getAddress(ecdsaAccount.address),
        );
        expect(runtime.packages).toEqual([
          {
            moduleType: 1,
            module: validator,
            moduleData: ecdsaAccount.address.toLowerCase(),
            internalData: encodeKernelV4ValidatorData({ hook: "none", selectors: [] }),
          },
        ]);
        return;
      }
      // The session installs the caller-bound signer module as its moduleType 6
      // package and signs inside Kernel's permission envelope.
      const signerPackage = runtime.packages[1];
      expect(signerPackage).toMatchObject({ moduleType: 6, module: customSigner });
      const [slices] = decodeAbiParameters([{ name: "signatures", type: "bytes[]" }], signature);
      expect(slices.length).toBe(2);
      const signerSlice = slices[1];
      if (!signerSlice) throw new Error("permission envelope carries no signer slice");
      expect(
        await recoverAddress({ hash: prepared.userOperationHash, signature: signerSlice }),
      ).toBe(getAddress(ecdsaAccount.address));
    },
  );

  it.each([
    ["a non-hex signature", "not-hex"],
    ["a non-string signature", 1],
    ["a signature of the wrong kind entirely", null],
  ] as const)("verifies %s as false rather than throwing", async (_label, signature) => {
    // The captured profile, not the caller's object: the boundary owns both the
    // mandatory self-verification and the shape of what it will verify at all.
    const key = ownerOperator({ key: customKey() }).key;
    expect(await key.verify(keccak256("0xdeadbeef"), signature as never)).toBe(false);
    expect(await key.verify("0x00" as never, key.dummySignature)).toBe(false);
  });

  it("refuses to sign anything that is not a 32-byte hash", async () => {
    const key = ownerOperator({ key: customKey() }).key;
    await expect(key.sign("0xdeadbeef")).rejects.toMatchObject({
      code: "kernel_runtime_input_invalid",
      message: "Kernel key profile signing hash is invalid",
    });
  });

  it.each([
    ["is not hex bytes at all", "nope"],
    ["is empty", "0x"],
    ["is not a string", 1],
  ] as const)("refuses a capability whose signature %s", async (_label, produced) => {
    const key = ownerOperator({
      key: customKey({ sign: () => Promise.resolve(produced as never) }),
    }).key;
    await expect(key.sign(keccak256("0xdeadbeef"))).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
      message: "Kernel key signature is invalid",
    });
  });

  it("maps a throwing consumer signing capability to one signing-failure code", async () => {
    const key = ownerOperator({
      key: customKey({
        sign: () => Promise.reject(new Error("credential-bearing provider detail")),
      }),
    }).key;
    await expect(key.sign(keccak256("0xdeadbeef"))).rejects.toMatchObject({
      code: "kernel_runtime_signing_failed",
      message: "Kernel key signing failed",
    });
  });

  it("refuses a signature the profile's own verification rejects", async () => {
    // Self-verification is mandatory at the capture boundary, so a consumer
    // profile cannot opt out of it: these bytes never reach an envelope.
    const foreign = privateKeyToAccount(`0x${"12".repeat(32)}`);
    const runtime = customRuntime(
      "owner",
      customKey({ sign: (hash) => foreign.sign({ hash }) as Promise<`0x${string}`> }),
    );
    const prepared = runtime.prepareOperation({
      ...operation,
      account: await runtime.bindAccount({
        accountIndex: "0",
        initialPackages: runtime.packages,
      }),
    });
    await expect(runtime.signOperation(prepared)).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
      message: "Kernel key signature does not verify against the bound public material",
    });
  });

  it("refuses a session whose consumer-authored key binds no signer module", () => {
    // No pinned module exists for a kind this SDK never reviewed, so a session
    // without a caller-bound signer module has no authority module at all. The
    // same key still composes owner authority, which needs only its validator.
    const key = customKey({ signerModule: null });
    expect(
      createKernelRuntime({ deployment, operator: ownerOperator({ key }), reads: reads() }),
    ).toMatchObject({ authority: "owner", keyKind: customKind, authorityModule: validator });
    expect(() => sessionOperator({ key, policies: [sessionScope] })).toThrowError(
      expect.objectContaining({
        name: "OaathKernelRuntimeError",
        code: "kernel_runtime_signer_unavailable",
      }),
    );
  });

  it("refuses an unscoped session for a consumer-authored key", () => {
    // Policies stay required on every kind: a session is a permission.
    expect(() => sessionOperator({ key: customKey(), policies: [] })).toThrowError(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );
  });

  it.each(["owner", "session"] as const)(
    "refuses to bind an account when the %s authority module carries no code",
    async (authority) => {
      const module = authority === "owner" ? validator : customSigner;
      const runtime = customRuntime(authority, customKey(), module);
      await expect(
        runtime.bindAccount({
          accountIndex: "0",
          initialPackages: customRuntime("owner").packages,
        }),
      ).rejects.toMatchObject({
        code:
          authority === "owner"
            ? "kernel_runtime_validator_unavailable"
            : "kernel_runtime_signer_unavailable",
        message: "Kernel authority module carries no code on this chain",
      });
    },
  );

  it("refuses to bind when the authority module code cannot be read", async () => {
    const runtime = createKernelRuntime({
      deployment,
      operator: operatorProfiles.session(customKey()),
      reads: { read: () => Promise.reject(new Error("provider detail")) },
    });
    await expect(
      runtime.bindAccount({ accountIndex: "0", initialPackages: runtime.packages }),
    ).rejects.toMatchObject({
      code: "kernel_runtime_signer_unavailable",
      message: "Kernel authority module code could not be read",
    });
  });

  it("refuses a reviewed kind that binds its own permission signer module", () => {
    // A caller may never select the module a reviewed credential installs.
    const key = ecdsaKey({ account: ecdsaAccount, validator });
    expect(() =>
      ownerOperator({ key: Object.freeze({ ...key, signerModule: customSigner }) }),
    ).toThrowError(
      expect.objectContaining({
        code: "kernel_runtime_input_invalid",
        message: "Kernel key profile of a reviewed kind may not bind a signer module",
      }),
    );
  });

  it.each([
    ["an unprefixed kind", "bls"],
    ["a bare prefix", "custom:"],
    ["an uppercase slug", "custom:Demo"],
    ["a slug opening with a hyphen", "custom:-demo"],
    ["a slug carrying a separator", "custom:demo/two"],
    ["a nested prefix", "custom:custom:demo"],
    ["an overlong slug", `custom:${"a".repeat(33)}`],
    ["a reviewed kind's name behind no prefix", "ECDSA"],
    ["a non-string kind", 1],
  ] as const)("refuses %s", (_label, kind) => {
    expect(() => ownerOperator({ key: customKey({ kind: kind as never }) })).toThrowError(
      expect.objectContaining({
        code: "kernel_runtime_input_invalid",
        message: "Kernel key profile kind is unsupported",
      }),
    );
  });

  it.each([
    ["a zero signer module", `0x${"00".repeat(20)}` as const],
    ["a truncated signer module", "0x1234" as const],
  ] as const)("refuses %s on a consumer-authored key", (_label, signerModule) => {
    expect(() =>
      sessionOperator({ key: customKey({ signerModule }), policies: [sessionScope] }),
    ).toThrowError(
      expect.objectContaining({
        code: "kernel_runtime_input_invalid",
        message: "Kernel key profile signer module is invalid",
      }),
    );
  });

  it("derives one permission ID per kind for the same key material and modules", () => {
    // The kind is hashed into the permission ID, so a consumer kind reusing
    // another's public material and modules still installs its own permission.
    const permissionId = (key: Readonly<KeyProfile>) => {
      const validation = sessionOperator({ key, policies: [sessionScope] }).resolveValidation(
        deployment,
      );
      if (validation.kind !== "permission") throw new Error("not a permission validation");
      return validation.permissionId;
    };
    expect(permissionId(customKey())).not.toBe(permissionId(customKey({ kind: "custom:other" })));
    expect(permissionId(customKey())).toBe(permissionId(customKey()));
  });
});

describe("Kernel key profiles", () => {
  it("signs and verifies through the ECDSA key profile", async () => {
    const key = keyProfiles.ecdsa();
    const hash = keccak256("0xdeadbeef");
    const signature = await key.sign(hash);
    expect(await key.verify(hash, signature)).toBe(true);
    expect(await key.verify(keccak256("0x00"), signature)).toBe(false);
    expect(await key.verify(hash, "0x1234")).toBe(false);
  });

  it("normalizes and verifies raw P-256 signatures", async () => {
    const key = keyProfiles.p256();
    const hash = keccak256("0xdeadbeef");
    const signature = await key.sign(hash);
    expect(signature).toMatch(/^0x[0-9a-f]{128}$/u);
    expect(await key.verify(hash, signature)).toBe(true);

    const order = p256.CURVE.n;
    const highS = p256Key({
      credential: p256Credential,
      async sign(request) {
        const low = await p256Sign(request);
        const s = order - BigInt(`0x${low.slice(66)}`);
        return `${low.slice(0, 66)}${s.toString(16).padStart(64, "0")}`;
      },
    });
    expect(await highS.sign(hash)).toBe(signature);
  });

  it.each([
    ["invalid width", async (): Promise<string> => "0x00"],
    ["zero scalars", async (): Promise<string> => `0x${"00".repeat(64)}`],
    ["unrelated key", async (): Promise<string> => `0x${"01".repeat(64)}`],
  ] as const)("fails closed on a P-256 capability returning %s", async (_label, sign) => {
    const key = p256Key({ credential: p256Credential, sign });
    await expect(key.sign(keccak256("0xdeadbeef"))).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
  });

  it("maps a failing P-256 capability to one signing-failure code", async () => {
    const key = p256Key({
      credential: p256Credential,
      sign() {
        return Promise.reject(new Error("credential-bearing authenticator detail"));
      },
    });
    await expect(key.sign(keccak256("0xdeadbeef"))).rejects.toMatchObject({
      code: "kernel_runtime_signing_failed",
      message: "P-256 key signing failed",
    });
  });

  it("verifies a WebAuthn assertion and encodes the Kernel signature envelope", async () => {
    const key = keyProfiles.webauthn();
    const hash = keccak256("0xdeadbeef");
    const signature = await key.sign(hash);
    expect(await key.verify(hash, signature)).toBe(true);
    expect(await key.verify(keccak256("0x00"), signature)).toBe(false);

    const [authenticatorData, clientDataJSON, , , , usePrecompiled] = decodeAbiParameters(
      [
        { name: "authenticatorData", type: "bytes" },
        { name: "clientDataJSON", type: "string" },
        { name: "responseTypeLocation", type: "uint256" },
        { name: "r", type: "uint256" },
        { name: "s", type: "uint256" },
        { name: "usePrecompiled", type: "bool" },
      ] as const,
      signature,
    );
    expect(authenticatorData.slice(0, 66)).toBe(sha256(stringToBytes(rpId)));
    expect(JSON.parse(clientDataJSON)).toMatchObject({
      type: "webauthn.get",
      challenge: base64Url(hexToBytes(hash)),
      origin,
    });
    expect(usePrecompiled).toBe(false);
  });

  it("normalizes a high-s WebAuthn assertion", async () => {
    const key = webauthnKey({
      credential: webauthnCredential,
      credentialId,
      rpId,
      origin,
      authenticate: webauthnAuthenticate({ highS: true }),
    });
    const hash = keccak256("0xdeadbeef");
    await expect(key.sign(hash)).resolves.toMatch(/^0x/u);
  });

  it.each([
    ["a foreign origin", { origin: "https://evil.example" }],
    ["a replayed challenge", { challenge: base64Url(hexToBytes(keccak256("0x01"))) }],
    ["a non-assertion type", { type: "webauthn.create" }],
    ["missing user verification", { flags: 0x01 }],
    ["a foreign relying party", { rpIdHash: keccak256("0x02") }],
  ] as const)("fails closed on an assertion with %s", async (_label, overrides) => {
    const key = webauthnKey({
      credential: webauthnCredential,
      credentialId,
      rpId,
      origin,
      authenticate: webauthnAuthenticate(overrides),
    });
    await expect(key.sign(keccak256("0xdeadbeef"))).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
  });

  it("rejects a WebAuthn assertion that is not an exact record", async () => {
    const key = webauthnKey({
      credential: webauthnCredential,
      credentialId,
      rpId,
      origin,
      authenticate: async () => Object.freeze({ authenticatorData: "0x", clientDataJSON: "{}" }),
    });
    await expect(key.sign(keccak256("0xdeadbeef"))).rejects.toMatchObject({
      code: "kernel_runtime_input_invalid",
    });
  });

  it("rejects an unverifiable WebAuthn envelope", async () => {
    const key = keyProfiles.webauthn();
    expect(await key.verify(keccak256("0x00"), "0x1234")).toBe(false);
    expect(
      await key.verify(
        keccak256("0x00"),
        encodeAbiParameters(
          [
            { name: "authenticatorData", type: "bytes" },
            { name: "clientDataJSON", type: "string" },
            { name: "responseTypeLocation", type: "uint256" },
            { name: "r", type: "uint256" },
            { name: "s", type: "uint256" },
            { name: "usePrecompiled", type: "bool" },
          ] as const,
          [`0x${"00".repeat(37)}`, "{}", 0n, 1n, 1n, true],
        ),
      ),
    ).toBe(false);
  });

  it.each([
    [
      "a credential of the wrong kind",
      () => p256Key({ credential: webauthnCredential, sign: p256Sign }),
    ],
    [
      "a credential ID that does not match its hash",
      () =>
        webauthnKey({
          credential: webauthnCredential,
          credentialId: "AAEC",
          rpId,
          origin,
          authenticate: webauthnAuthenticate(),
        }),
    ],
    [
      "a non-canonical credential ID",
      () =>
        webauthnKey({
          credential: webauthnCredential,
          credentialId: `${credentialId}=`,
          rpId,
          origin,
          authenticate: webauthnAuthenticate(),
        }),
    ],
    [
      "an insecure origin",
      () =>
        webauthnKey({
          credential: webauthnCredential,
          credentialId,
          rpId,
          origin: "http://app.example",
          authenticate: webauthnAuthenticate(),
        }),
    ],
    [
      "a traversing relying party",
      () =>
        webauthnKey({
          credential: webauthnCredential,
          credentialId,
          rpId: "app..example",
          origin,
          authenticate: webauthnAuthenticate(),
        }),
    ],
    [
      "a missing signing capability",
      () => p256Key({ credential: p256Credential, sign: null as never }),
    ],
    [
      "an ECDSA account without an address",
      () => ecdsaKey({ account: { sign: async () => "0x" } as never, validator }),
    ],
  ] as const)("rejects %s", (_label, build) => {
    expect(build).toThrowError(expect.objectContaining({ code: "kernel_runtime_input_invalid" }));
  });

  it("rejects validator resolution against a deployment profile it does not own", () => {
    const key = keyProfiles.ecdsa();
    expect(() => key.resolveValidator({ ...deployment })).toThrowError(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );
    expect(key.resolveValidator(deployment)).toBe(validator);
  });

  it("fails closed on an ECDSA capability returning a malformed signature", async () => {
    const key = ecdsaKey({
      account: { address: ecdsaAccount.address, sign: async () => "0xdead" },
      validator,
    });
    await expect(key.sign(keccak256("0x00"))).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
    });
  });

  it("fails closed on an ECDSA signature from an unrelated key", async () => {
    const other = privateKeyToAccount(`0x${"12".repeat(32)}`);
    const key = ecdsaKey({
      account: { address: ecdsaAccount.address, sign: (request) => other.sign(request) },
      validator,
    });
    await expect(key.sign(keccak256("0x00"))).rejects.toMatchObject({
      code: "kernel_runtime_signature_invalid",
      message: "ECDSA signature does not match the bound key",
    });
  });
});

describe("Kernel module registry", () => {
  const kinds = ["ecdsa", "p256", "webauthn"] as const satisfies readonly KernelBuiltInKeyKind[];

  it("pins the reviewed permission signer modules and leaves unbound axes null", () => {
    // Addresses are chain-independent by construction: the registry takes no
    // chain, so the same fact holds wherever a supported deployment exists. The
    // local composition proof deploys these exact addresses through CREATE2.
    expect(kinds.map((kind) => pinnedSignerModule(kind))).toEqual([
      "0x6a6f069e2a08c2468e7724ab3250cdbfba14d4ff",
      null,
      "0x8b2df925aa16071fcdf0053768420e242935ac65",
    ]);
  });

  it("pins nothing for a consumer-authored kind", () => {
    // Pluggability never widens the reviewed registry: a custom kind resolves no
    // module on either axis, which is why it must bind its own and have them
    // code-proven on the action chain.
    for (const kind of [customKind, "custom:other"] as const satisfies readonly KernelKeyKind[]) {
      expect(pinnedSignerModule(kind)).toBeNull();
    }
  });

  it("pins one reviewed policy module per bounded axis", () => {
    // CallPolicy enforces calls and their per-call value ceilings from one
    // configuration; value is not a separate axis.
    expect(
      (["call", "expiry", "operation-limit"] as const).map((kind) => pinnedPolicyModule(kind)),
    ).toEqual([
      "0x9a52283276a0ec8740df50bf01b28a80d880eaf2",
      "0xb9f8f524be6ecd8c945b1b87f9ae5c192fdce20f",
      "0xf63d4139b25c836334edd76641356c6b74c86873",
    ]);
  });

  it("publishes the signer material each pinned module installs", () => {
    // ECDSASigner.onInstall requires exactly the 20-byte signer address, and
    // WebAuthnSigner.onInstall decodes (uint256, uint256, bytes32); a drift in
    // either public material would install a permission signer that can never
    // validate.
    expect(keyProfiles.ecdsa().publicMaterial).toMatch(/^0x[0-9a-f]{40}$/u);
    expect(keyProfiles.webauthn().publicMaterial).toMatch(/^0x[0-9a-f]{192}$/u);
  });
});

describe("Kernel permission policy compilation", () => {
  const spender = `0x${"55".repeat(20)}` as const;
  const transferSelector = "0xa9059cbb" as const;
  const permissions = [
    { target, selector: KERNEL_V4_EXECUTE_SELECTOR, valueLimit: "0" },
    { target: spender, selector: transferSelector, valueLimit: "1000" },
    { target: spender, selector: "0x00000000" as const, valueLimit: "25" },
  ] as const;
  const PERMISSIONS = [
    {
      name: "permissions",
      type: "tuple[]",
      components: [
        { name: "callType", type: "bytes1" },
        { name: "target", type: "address" },
        { name: "selector", type: "bytes4" },
        { name: "valueLimit", type: "uint256" },
        {
          name: "rules",
          type: "tuple[]",
          components: [
            { name: "condition", type: "uint8" },
            { name: "offset", type: "uint64" },
            { name: "params", type: "bytes32[]" },
          ],
        },
      ],
    },
  ] as const;

  it("compiles one CallPolicy permission per allowed call with its exact value limit", () => {
    const policy = compileKernelPermissionPolicy([{ kind: "call", permissions }]);
    expect(policy).toMatchObject({
      validUntil: null,
      maximumOperations: null,
    });
    expect(policy.packages.map((entry) => entry.module)).toEqual([pinnedPolicyModule("call")]);
    expect(policy.permissions).toEqual(permissions);
    expect(Object.isFrozen(policy)).toBe(true);
    // Every permitted (callType, target, selector) entry carries exactly the
    // value ceiling reviewed for that call: a zero-value call stays at zero
    // even though another call in the same scope may spend 1000 wei. No global
    // maximum widens a sibling entry.
    const callPackage = policy.packages[0];
    if (!callPackage) throw new Error("no call policy package");
    const [decoded] = decodeAbiParameters(PERMISSIONS, callPackage.policyData);
    expect(
      decoded.map((permission) => [
        permission.callType,
        permission.target,
        permission.selector,
        permission.valueLimit,
        permission.rules.length,
      ]),
    ).toEqual([
      ["0x00", target, KERNEL_V4_EXECUTE_SELECTOR, 0n, 0],
      ["0x00", spender, transferSelector, 1000n, 0],
      ["0x00", spender, "0x00000000", 25n, 0],
    ]);
  });

  it("compiles a call with no declared spend to a zero ceiling", () => {
    // A call that never declared a spend may not move value: CallPolicy
    // reverts CallViolatesValueRule above the ceiling, so zero is the closed
    // default rather than an unlimited sentinel.
    const policy = compileKernelPermissionPolicy([{ kind: "call", permissions: [permissions[0]] }]);
    expect(policy.permissions.map((one) => one.valueLimit)).toEqual(["0"]);
    const only = policy.packages[0];
    if (!only) throw new Error("no call policy package");
    expect(
      decodeAbiParameters(PERMISSIONS, only.policyData)[0].map((one) => one.valueLimit),
    ).toEqual([0n]);
  });

  it("compiles the expiry axis into the exact TimestampPolicy install payload", () => {
    // TimestampPolicy._policyOninstall decodes abi.encode(ValidAfter, ValidUntil),
    // two uint48 words; checkUserOpPolicy returns them as the ERC-4337 packed
    // range, so EntryPoint refuses an expired session with AA22.
    const policy = compileKernelPermissionPolicy([
      { kind: "call", permissions },
      { kind: "expiry", validAfter: "1750000000", validUntil: "1750003600" },
    ]);
    expect(policy).toMatchObject({ validAfter: "1750000000", validUntil: "1750003600" });
    expect(policy.packages.map((entry) => entry.module)).toEqual([
      pinnedPolicyModule("call"),
      pinnedPolicyModule("expiry"),
    ]);
    const expiryPackage = policy.packages[1];
    if (!expiryPackage) throw new Error("no expiry policy package");
    expect(
      decodeAbiParameters(
        [
          { name: "validAfter", type: "uint48" },
          { name: "validUntil", type: "uint48" },
        ],
        expiryPackage.policyData,
      ),
    ).toEqual([1_750_000_000, 1_750_003_600]);
  });

  it("compiles the operation-limit axis into a pure per-chain count cap", () => {
    // RateLimitPolicy.onInstall reads packed uint48 interval, count and startAt. A
    // zero interval and start make it a count cap with no time bound: every
    // validated operation decrements count, and an exhausted count returns
    // Kernel's signature-failure sentinel.
    const policy = compileKernelPermissionPolicy([
      { kind: "call", permissions },
      { kind: "operation-limit", maximumOperations: "5" },
    ]);
    expect(policy.maximumOperations).toBe("5");
    const limitPackage = policy.packages[1];
    if (!limitPackage) throw new Error("no operation limit policy package");
    expect(limitPackage.module).toBe(pinnedPolicyModule("operation-limit"));
    expect(limitPackage.policyData).toBe(
      concat([toHex(0, { size: 6 }), toHex(5, { size: 6 }), toHex(0, { size: 6 })]),
    );
  });

  it.each(["expiry", "operation-limit"] as const)(
    "refuses the %s axis alone, which bounds no call at all",
    (kind) => {
      const profile =
        kind === "expiry"
          ? { kind, validAfter: "0", validUntil: "1750000000" }
          : { kind, maximumOperations: "5" };
      expect(
        compileKernelPermissionPolicy([{ kind: "call", permissions }, profile] as never).packages,
      ).toHaveLength(2);
      expect(() => compileKernelPermissionPolicy([profile] as never)).toThrowError(
        expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
      );
    },
  );

  it.each([
    ["an empty profile set", []],
    [
      "a duplicate kind",
      [
        { kind: "call", permissions: [permissions[0]] },
        { kind: "call", permissions: [permissions[1]] },
      ],
    ],
    ["an unsupported kind", [{ kind: "gas" }]],
    // The retired global value axis widened every call to the largest approved
    // allowance; it is no longer expressible at all.
    ["the retired global value kind", [{ kind: "value", maximumValue: "1" }]],
    [
      "a duplicate call",
      [
        {
          kind: "call",
          permissions: [
            { target, selector: KERNEL_V4_EXECUTE_SELECTOR, valueLimit: "0" },
            // The same (target, selector) with a different limit: one entry
            // would silently shadow the other's ceiling.
            { target, selector: KERNEL_V4_EXECUTE_SELECTOR, valueLimit: "5" },
          ],
        },
      ],
    ],
    [
      "a permission with no value limit",
      [{ kind: "call", permissions: [{ target, selector: KERNEL_V4_EXECUTE_SELECTOR }] }],
    ],
    [
      "a non-decimal value limit",
      [
        {
          kind: "call",
          permissions: [{ target, selector: KERNEL_V4_EXECUTE_SELECTOR, valueLimit: "0x01" }],
        },
      ],
    ],
    ["an empty permission set", [{ kind: "call", permissions: [] }]],
    ["a non-array profile set", { kind: "call", permissions }],
    ["a profile set with a hole", [undefined]],
  ] as const)("fails closed on %s", (_label, profiles) => {
    expect(() => compileKernelPermissionPolicy(profiles as never)).toThrowError(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );
  });

  it("rejects a session with no policy at all", () => {
    // An unscoped session is not expressible: without a policy the signer would
    // hold whole-key authority, which is what a permission exists to replace.
    expect(() => sessionOperator({ key: keyProfiles.ecdsa(), policies: [] })).toThrowError(
      expect.objectContaining({
        name: "OaathKernelRuntimeError",
        code: "kernel_runtime_input_invalid",
      }),
    );
  });

  it("derives one permission ID per distinct scope, key and module set", () => {
    const permissionId = (operator: ReturnType<typeof sessionOperator>) => {
      const validation = operator.resolveValidation(deployment);
      if (validation.kind !== "permission") throw new Error("not a permission validation");
      return validation.permissionId;
    };
    const scope = { kind: "call", permissions } as const;
    const key = keyProfiles.ecdsa();
    const first = permissionId(sessionOperator({ key, policies: [scope] }));
    // Same scope and same key material derive the same ID on every chain, so a
    // restored session addresses the permission it installed.
    expect(permissionId(sessionOperator({ key: keyProfiles.ecdsa(), policies: [scope] }))).toBe(
      first,
    );
    // Changing any single call's value limit is a different permission: the
    // limit is part of the encoded CallPolicy payload, so the installed
    // authority can never be addressed by an ID minted for another ceiling.
    expect(
      permissionId(
        sessionOperator({
          key,
          policies: [
            {
              kind: "call",
              permissions: [
                permissions[0],
                { ...permissions[1], valueLimit: "1001" },
                permissions[2],
              ],
            },
          ],
        }),
      ),
    ).not.toBe(first);
    // A tighter scope is a different permission, never the same one widened.
    expect(
      permissionId(
        sessionOperator({ key, policies: [{ kind: "call", permissions: [permissions[0]] }] }),
      ),
    ).not.toBe(first);
  });
});
