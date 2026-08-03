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
  recoverAddress,
  sha256,
  stringToBytes,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import {
  composeKernelHooks,
  createKernelRuntime,
  ecdsaKey,
  encodeKernelV4ValidatorData,
  KERNEL_V4_ENTRY_POINT_V07,
  KERNEL_V4_ENTRY_POINT_V07_CODE_HASH,
  KERNEL_V4_EXECUTE_SELECTOR,
  KERNEL_V4_EXECUTE_USER_OP_SELECTOR,
  KERNEL_V4_FACTORY_V07_CODE_HASH,
  KERNEL_V4_UUPS_IMPLEMENTATION_V07,
  type KernelKeyKind,
  type KernelOperatorAuthority,
  type KernelV4AccountReadRequest,
  type KeyProfile,
  kernelV4Deployment,
  type OperatorProfile,
  ownerOperator,
  p256Key,
  pinnedSignerModule,
  sessionOperator,
  webauthnKey,
} from "../src/index.js";

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

function reads(state: "counterfactual" | "deployed" = "counterfactual") {
  return {
    async read(request: KernelV4AccountReadRequest): Promise<unknown> {
      if (request.type === "chain_id") return request.chainId;
      if (request.type === "runtime_code_hash") return runtimeCodeHash(request.address);
      if (request.type === "code") {
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

const keyProfiles: Readonly<Record<KernelKeyKind, () => Readonly<KeyProfile>>> = Object.freeze({
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
});

const operatorProfiles: Readonly<
  Record<KernelOperatorAuthority, (key: Readonly<KeyProfile>) => Readonly<OperatorProfile>>
> = Object.freeze({
  owner: (key) => ownerOperator({ key }),
  session: (key) => sessionOperator({ key, hooks: [] }),
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
  const matrix: readonly (readonly [KernelKeyKind, KernelOperatorAuthority])[] = [
    ["ecdsa", "owner"],
    ["ecdsa", "session"],
    ["p256", "owner"],
    ["p256", "session"],
    ["webauthn", "owner"],
    ["webauthn", "session"],
  ];

  it.each(matrix)(
    "composes the %s key with %s authority through one factory",
    (kind, authority) => {
      const key = keyProfiles[kind]();
      expect(key.kind).toBe(kind);
      const operator = operatorProfiles[authority](key);
      expect(operator).toMatchObject({ authority, policy: null });
      expect(operator.key.kind).toBe(kind);
      const compose = () => createKernelRuntime({ deployment, operator, reads: reads() });

      // Kernel v4 pins no reviewed raw P-256 or WebAuthn validator module, so both
      // kinds fail closed on the same axis instead of being skipped.
      if (kind !== "ecdsa") {
        expect(compose).toThrowError(
          expect.objectContaining({
            name: "OaathKernelRuntimeError",
            code: "kernel_runtime_validator_unavailable",
          }),
        );
        return;
      }

      const runtime = compose();
      expect(runtime).toMatchObject({ authority, keyKind: kind, validator, deployment });
      expect(runtime.validation).toEqual(
        authority === "owner" ? { kind: "root" } : { kind: "validator", validator },
      );
      expect(runtime.packages).toEqual([
        {
          moduleType: 1,
          module: validator,
          moduleData: ecdsaAccount.address.toLowerCase(),
          internalData: encodeKernelV4ValidatorData({
            hook: "none",
            selectors: authority === "owner" ? [] : [KERNEL_V4_EXECUTE_SELECTOR],
          }),
        },
      ]);
      expect(runtime.dummySignature).toBe(key.dummySignature);
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
      expect(prepared.userOperation.callData.startsWith(KERNEL_V4_EXECUTE_USER_OP_SELECTOR)).toBe(
        authority === "session",
      );
      expect(prepared.chainId).toBe(chainId);

      const signature = await runtime.signOperation(prepared);
      expect(await recoverAddress({ hash: prepared.userOperationHash, signature })).toBe(
        getAddress(ecdsaAccount.address),
      );
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
  const kinds = ["ecdsa", "p256", "webauthn"] as const satisfies readonly KernelKeyKind[];

  it("pins the reviewed permission signer modules and leaves unbound axes null", () => {
    // Addresses are chain-independent by construction: the registry takes no
    // chain, so the same fact holds wherever a supported deployment exists. The
    // local composition proof deploys these exact addresses through CREATE2.
    expect(kinds.map((kind) => pinnedSignerModule(kind))).toEqual([
      "0xd4c7dec43e67ffe3dcca0aeb71556123d3194e1d",
      null,
      "0x8b2df925aa16071fcdf0053768420e242935ac65",
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

describe("Kernel policy hook composition", () => {
  const calls = [
    { target, selectors: [KERNEL_V4_EXECUTE_SELECTOR] },
    { target: `0x${"55".repeat(20)}` as const, selectors: [] },
  ];

  it("combines every policy axis into one module configuration", () => {
    const policy = composeKernelHooks([
      { kind: "call", calls },
      { kind: "value", maximumValue: "1000" },
      { kind: "expiry", validAfter: "10", validUntil: "20" },
      { kind: "operation-limit", maximumOperations: "5" },
    ]);
    expect(policy).toMatchObject({
      maximumValue: "1000",
      validAfter: "10",
      validUntil: "20",
      maximumOperations: "5",
    });
    expect(policy.calls).toEqual(calls);
    expect(policy.moduleData).toMatch(/^0x[0-9a-f]+$/u);
    expect(Object.isFrozen(policy)).toBe(true);
  });

  it("encodes unlimited sentinels for absent axes", () => {
    const policy = composeKernelHooks([{ kind: "call", calls }]);
    expect(policy).toMatchObject({
      maximumValue: null,
      validAfter: null,
      validUntil: null,
      maximumOperations: null,
    });
    expect(
      decodeAbiParameters(
        [
          {
            name: "calls",
            type: "tuple[]",
            components: [
              { name: "target", type: "address" },
              { name: "selectors", type: "bytes4[]" },
            ],
          },
          { name: "maximumValue", type: "uint256" },
          { name: "validAfter", type: "uint48" },
          { name: "validUntil", type: "uint48" },
          { name: "maximumOperations", type: "uint32" },
        ] as const,
        policy.moduleData,
      ).slice(1),
    ).toEqual([(1n << 256n) - 1n, 0, 0, 0]);
  });

  it.each([
    ["an empty profile set", []],
    [
      "a duplicate kind",
      [
        { kind: "value", maximumValue: "1" },
        { kind: "value", maximumValue: "2" },
      ],
    ],
    ["an unsupported kind", [{ kind: "gas" }]],
    ["an inverted validity window", [{ kind: "expiry", validAfter: "20", validUntil: "10" }]],
    ["a zero operation limit", [{ kind: "operation-limit", maximumOperations: "0" }]],
    [
      "a duplicate call target",
      [
        {
          kind: "call",
          calls: [
            { target, selectors: [] },
            { target, selectors: [] },
          ],
        },
      ],
    ],
    [
      "a duplicate selector",
      [
        {
          kind: "call",
          calls: [{ target, selectors: [KERNEL_V4_EXECUTE_SELECTOR, KERNEL_V4_EXECUTE_SELECTOR] }],
        },
      ],
    ],
    ["an empty call set", [{ kind: "call", calls: [] }]],
  ] as const)("fails closed on %s", (_label, profiles) => {
    expect(() => composeKernelHooks(profiles as never)).toThrowError(
      expect.objectContaining({ code: "kernel_runtime_input_invalid" }),
    );
  });

  it("fails closed when a composed policy has no reviewed Kernel v4 hook module", () => {
    const operator = sessionOperator({
      key: keyProfiles.ecdsa(),
      hooks: [{ kind: "expiry", validAfter: "0", validUntil: "1750000000" }],
    });
    expect(operator.policy).toMatchObject({ validUntil: "1750000000" });
    expect(() => createKernelRuntime({ deployment, operator, reads: reads() })).toThrowError(
      expect.objectContaining({
        name: "OaathKernelRuntimeError",
        code: "kernel_runtime_hook_unavailable",
      }),
    );
  });
});
