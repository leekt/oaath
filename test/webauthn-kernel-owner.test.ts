import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/nist.js";
import { concatHex, decodeAbiParameters, hexToBytes, keccak256, sha256, toHex } from "viem";
import { entryPoint07Address } from "viem/account-abstraction";
import { describe, expect, it, vi } from "vitest";
import {
  createWebAuthnKernelOwnerRuntime,
  type KernelAccountProfile,
  OgpWebAuthnKernelOwnerError,
  prepareUserOperation,
  type WebAuthnKernelOwnerRestorationReadRequest,
  type WebAuthnKernelOwnerRuntime,
  type WebAuthnOwnerAssertion,
} from "../src/index.js";

const TEXT = new TextEncoder();
const ASSERTION_PARAMETERS = [
  { name: "authenticatorData", type: "bytes" },
  { name: "clientDataJSON", type: "string" },
  { name: "responseTypeLocation", type: "uint256" },
  { name: "r", type: "uint256" },
  { name: "s", type: "uint256" },
  { name: "usePrecompiled", type: "bool" },
] as const;
const otherAddress = `0x${"99".repeat(20)}` as const;
const artifacts = JSON.parse(
  readFileSync(new URL("./fixtures/kernel-v3.3-bytecode.json", import.meta.url), "utf8"),
) as Record<
  "webauthnValidator" | "p256Verifier",
  { creationBytecode: Hex; runtimeByteLength: number }
>;
type Hex = `0x${string}`;

function runtimeCode(contract: "webauthn_validator" | "p256_verifier"): Hex {
  const artifact =
    artifacts[contract === "webauthn_validator" ? "webauthnValidator" : "p256Verifier"];
  return `0x${artifact.creationBytecode.slice(-(artifact.runtimeByteLength * 2))}`;
}

function lower(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function profile(
  publicKey: `0x${string}`,
  authenticatorIdHash: `0x${string}`,
  options: {
    accountIndex?: string;
    factoryRoute?: "kernel_factory" | "meta_factory";
  } = {},
): KernelAccountProfile {
  return {
    version: "ogp.kernel-account-profile/v1",
    kind: "kernel",
    accountIndex: options.accountIndex ?? "0",
    kernelVersion: "0.3.3",
    factoryRoute: options.factoryRoute ?? "kernel_factory",
    entryPoint: { version: "0.7" },
    ownerCredential: {
      version: "ogp.owner-credential-profile/v1",
      kind: "webauthn",
      publicKey,
      authenticatorIdHash,
    },
  };
}

function assertionForHash(
  hash: `0x${string}`,
  privateKey: Uint8Array,
  rpId: string,
  overrides: Partial<WebAuthnOwnerAssertion> = {},
): WebAuthnOwnerAssertion {
  const challenge = base64url(hexToBytes(hash));
  const clientDataJSON =
    overrides.clientDataJSON ??
    `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://example.test","crossOrigin":false}`;
  const authenticatorData =
    overrides.authenticatorData ??
    concatHex([sha256(toHex(TEXT.encode(rpId))), "0x05", "0x00000000"]);
  const messageHash = sha256(
    concatHex([authenticatorData, sha256(toHex(TEXT.encode(clientDataJSON)))]),
  );
  const signature = p256.sign(hexToBytes(messageHash), privateKey, { lowS: true });
  return {
    authenticatorData,
    clientDataJSON,
    responseTypeLocation: overrides.responseTypeLocation ?? "1",
    r: overrides.r ?? toHex(signature.r, { size: 32 }),
    s: overrides.s ?? toHex(signature.s, { size: 32 }),
  };
}

function owner(
  options: {
    privateKey?: Uint8Array;
    authenticatorBytes?: Uint8Array;
    rpId?: string;
    assertion?: (
      hash: `0x${string}`,
      privateKey: Uint8Array,
      rpId: string,
    ) => unknown | Promise<unknown>;
  } = {},
) {
  const privateKey = options.privateKey ?? p256.utils.randomPrivateKey();
  const authenticatorBytes =
    options.authenticatorBytes ?? crypto.getRandomValues(new Uint8Array(32));
  const publicKey = lower(toHex(p256.getPublicKey(privateKey, false)));
  const authenticatorId = base64url(authenticatorBytes);
  const authenticatorIdHash = keccak256(toHex(authenticatorBytes));
  const rpId = options.rpId ?? "example.test";
  let calls = 0;
  return {
    privateKey,
    authenticatorBytes,
    publicKey,
    authenticatorId,
    authenticatorIdHash,
    rpId,
    capability: {
      publicKey,
      authenticatorId,
      authenticatorIdHash,
      rpId,
      async signMessageHash({ hash }: { hash: `0x${string}` }) {
        calls += 1;
        return options.assertion
          ? options.assertion(hash, privateKey, rpId)
          : assertionForHash(hash, privateKey, rpId);
      },
    },
    calls: () => calls,
  };
}

function cloneOwner(current: ReturnType<typeof owner>) {
  return owner({
    privateKey: current.privateKey,
    authenticatorBytes: current.authenticatorBytes,
  });
}

function prepared(
  runtime: WebAuthnKernelOwnerRuntime,
  overrides: {
    chainId?: number;
    entryPoint?: `0x${string}`;
    sender?: `0x${string}`;
    factory?: { address: `0x${string}`; data: `0x${string}` } | null;
  } = {},
) {
  return prepareUserOperation({
    kind: "execution",
    grantId: "grant-webauthn-owner",
    chainId: overrides.chainId ?? runtime.action.chainId,
    entryPoint: {
      version: "0.7",
      address: overrides.entryPoint ?? lower(entryPoint07Address),
    },
    userOperation: {
      sender: overrides.sender ?? runtime.accountAddress,
      nonce: "0",
      callData: "0x",
      callGasLimit: "300000",
      verificationGasLimit: "500000",
      preVerificationGas: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
      factory: overrides.factory === undefined ? runtime.factory : overrides.factory,
      paymaster: null,
    },
  });
}

async function runtime(
  current = owner(),
  options: {
    chainId?: number;
    accountIndex?: string;
    factoryRoute?: "kernel_factory" | "meta_factory";
  } = {},
) {
  return {
    owner: current,
    runtime: await createWebAuthnKernelOwnerRuntime({
      profile: profile(current.publicKey, current.authenticatorIdHash, options),
      chainId: options.chainId ?? 31_337,
      signer: current.capability,
    }),
  };
}

async function expectCode(action: () => Promise<unknown>, code: string) {
  await expect(action()).rejects.toMatchObject({ code });
}

function restorationEvidence(
  request: WebAuthnKernelOwnerRestorationReadRequest,
  current: Awaited<ReturnType<typeof runtime>>,
): unknown {
  if (request.type === "chain_id") return 31_337;
  if (request.type === "account_code") return "0x6000";
  if (request.type === "kernel_root_validator") {
    return `0x01${current.runtime.validatorAddress.slice(2)}`;
  }
  if (request.type === "runtime_code") return runtimeCode(request.contract);
  if (request.type === "webauthn_validator_initialized") return true;
  return current.owner.publicKey;
}

describe("WebAuthn Kernel owner runtime", () => {
  it("derives, recreates, and signs one exact patched WebAuthn owner", async () => {
    const firstOwner = owner();
    const direct = await runtime(firstOwner, { accountIndex: "17" });
    const recreated = await runtime(cloneOwner(firstOwner), { accountIndex: "17" });
    const meta = await runtime(cloneOwner(firstOwner), {
      accountIndex: "17",
      factoryRoute: "meta_factory",
    });
    const otherChain = await runtime(cloneOwner(firstOwner), {
      chainId: 1_000_001,
      accountIndex: "17",
    });

    expect(recreated.runtime.accountAddress).toBe(direct.runtime.accountAddress);
    expect(meta.runtime.accountAddress).toBe(direct.runtime.accountAddress);
    expect(otherChain.runtime.accountAddress).toBe(direct.runtime.accountAddress);
    expect(direct.runtime.validatorAddress).toBe("0x7ab16ff354acb328452f1d445b3ddee9a91e9e69");
    const signature = await direct.runtime.signPreparedUserOperation(prepared(direct.runtime));
    const decoded = decodeAbiParameters(ASSERTION_PARAMETERS, signature);
    expect(decoded[5]).toBe(false);
    expect(firstOwner.calls()).toBe(1);
  });

  it("binds authenticator identity into account derivation without a chain policy", async () => {
    const firstOwner = owner();
    const secondOwner = owner({
      privateKey: firstOwner.privateKey,
      authenticatorBytes: crypto.getRandomValues(new Uint8Array(32)),
    });
    const first = await runtime(firstOwner);
    const second = await runtime(secondOwner);
    expect(second.runtime.accountAddress).not.toBe(first.runtime.accountAddress);
    expect(await runtime(firstOwner, { chainId: 9_999_991 })).toMatchObject({
      runtime: { accountAddress: first.runtime.accountAddress },
    });
  });

  it("requires exact deployed state before signing an operation without factory data", async () => {
    const current = await runtime();
    const operation = prepared(current.runtime, { factory: null });
    await expectCode(
      () => current.runtime.signPreparedUserOperation(operation),
      "webauthn_kernel_owner_restoration_required",
    );
    const restored = await current.runtime.restore({
      async read(request: WebAuthnKernelOwnerRestorationReadRequest) {
        return restorationEvidence(request, current);
      },
    });
    expect(restored.status).toBe("deployed");
    expect(restored.authenticatorIdHash).toBe(current.owner.authenticatorIdHash);
    await current.runtime.signPreparedUserOperation(operation);
    expect(current.owner.calls()).toBe(1);
  });

  it("distinguishes absent, unavailable, unreadable, and mismatched restoration", async () => {
    const cases: readonly [
      (
        request: WebAuthnKernelOwnerRestorationReadRequest,
        current: Awaited<ReturnType<typeof runtime>>,
      ) => unknown,
      string,
    ][] = [
      [
        () => Promise.reject(new Error("provider secret")),
        "webauthn_kernel_owner_restoration_unavailable",
      ],
      [() => "0x7a69", "webauthn_kernel_owner_restoration_unreadable"],
      [
        (request, current) =>
          request.type === "runtime_code"
            ? `0x${"00".repeat(artifacts.webauthnValidator.runtimeByteLength)}`
            : restorationEvidence(request, current),
        "webauthn_kernel_owner_binding_mismatch",
      ],
      [
        (request, current) =>
          request.type === "account_code" ? "0x" : restorationEvidence(request, current),
        "webauthn_kernel_owner_restoration_absent",
      ],
      [
        (request, current) =>
          request.type === "webauthn_validator_initialized"
            ? false
            : restorationEvidence(request, current),
        "webauthn_kernel_owner_restoration_absent",
      ],
      [
        (request, current) =>
          request.type === "webauthn_validator_public_key"
            ? lower(toHex(p256.getPublicKey(p256.utils.randomPrivateKey(), false)))
            : restorationEvidence(request, current),
        "webauthn_kernel_owner_binding_mismatch",
      ],
    ];
    for (const [response, code] of cases) {
      const current = await runtime();
      await expectCode(
        () =>
          current.runtime.restore({
            read(request: WebAuthnKernelOwnerRestorationReadRequest) {
              return Promise.resolve(response(request, current));
            },
          }),
        code,
      );
      expect(current.owner.calls()).toBe(0);
    }
  });

  it("rejects identity and prepared-operation substitutions before signing", async () => {
    const currentOwner = owner();
    const current = await runtime(currentOwner);
    const other = owner();
    await expectCode(
      () =>
        createWebAuthnKernelOwnerRuntime({
          profile: profile(currentOwner.publicKey, currentOwner.authenticatorIdHash),
          chainId: 31_337,
          signer: other.capability,
        }),
      "webauthn_kernel_owner_binding_mismatch",
    );
    const wrongId = owner({
      privateKey: currentOwner.privateKey,
      authenticatorBytes: crypto.getRandomValues(new Uint8Array(32)),
    });
    await expectCode(
      () =>
        createWebAuthnKernelOwnerRuntime({
          profile: profile(currentOwner.publicKey, currentOwner.authenticatorIdHash),
          chainId: 31_337,
          signer: wrongId.capability,
        }),
      "webauthn_kernel_owner_binding_mismatch",
    );

    for (const substitute of [
      prepared(current.runtime, { chainId: 31_338 }),
      prepared(current.runtime, { entryPoint: `0x${"11".repeat(20)}` }),
      prepared(current.runtime, { sender: otherAddress }),
      prepared(current.runtime, { factory: { ...current.runtime.factory, address: otherAddress } }),
      prepared(current.runtime, { factory: { ...current.runtime.factory, data: "0x00" } }),
    ]) {
      await expectCode(
        () => current.runtime.signPreparedUserOperation(substitute),
        "webauthn_kernel_owner_binding_mismatch",
      );
    }
    expect(currentOwner.calls()).toBe(0);
  });

  it("validates the structured assertion and canonical P-256 signature locally", async () => {
    const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    const mutations: Array<(hash: `0x${string}`, privateKey: Uint8Array, rpId: string) => unknown> =
      [
        (hash, key, rpId) => ({ ...assertionForHash(hash, key, rpId), extra: true }),
        (hash, key, rpId) => assertionForHash(hash, key, rpId, { responseTypeLocation: "2" }),
        (hash, key, rpId) =>
          assertionForHash(hash, key, rpId, {
            clientDataJSON: `{"type":"webauthn.create","challenge":"${base64url(hexToBytes(hash))}"}`,
          }),
        (hash, key, rpId) =>
          assertionForHash(hash, key, rpId, {
            authenticatorData: concatHex([sha256(toHex(TEXT.encode(rpId))), "0x01", "0x00000000"]),
          }),
        (hash, key, rpId) =>
          assertionForHash(hash, key, rpId, {
            authenticatorData: concatHex([sha256(toHex(TEXT.encode(rpId))), "0x15", "0x00000000"]),
          }),
        (hash, key, rpId) =>
          assertionForHash(hash, key, rpId, { s: toHex(P256_ORDER - 1n, { size: 32 }) }),
        (hash, _key, rpId) => assertionForHash(hash, p256.utils.randomPrivateKey(), rpId),
      ];
    for (const assertion of mutations) {
      const current = await runtime(owner({ assertion }));
      await expectCode(
        () => current.runtime.signPreparedUserOperation(prepared(current.runtime)),
        "webauthn_kernel_owner_signing_failed",
      );
    }
  });

  it("captures inputs once, rejects hostile shapes, and sanitizes failures", async () => {
    const currentOwner = owner();
    const mutableProfile = profile(currentOwner.publicKey, currentOwner.authenticatorIdHash);
    const mutableSigner = { ...currentOwner.capability };
    const captured = await createWebAuthnKernelOwnerRuntime({
      profile: mutableProfile,
      chainId: 31_337,
      signer: mutableSigner,
    });
    mutableSigner.signMessageHash = async () => {
      throw new Error("mutated signer secret");
    };
    await captured.signPreparedUserOperation(prepared(captured));

    const accessor = Object.defineProperty({ ...currentOwner.capability }, "authenticatorId", {
      enumerable: true,
      get: vi.fn(() => currentOwner.authenticatorId),
    });
    for (const hostile of [accessor, { ...currentOwner.capability, extra: true }]) {
      await expectCode(
        () =>
          createWebAuthnKernelOwnerRuntime({
            profile: profile(currentOwner.publicKey, currentOwner.authenticatorIdHash),
            chainId: 31_337,
            signer: hostile,
          }),
        "webauthn_kernel_owner_signer_invalid",
      );
    }

    const failed = await runtime(
      owner({
        assertion: async () => {
          throw new Error("provider secret material");
        },
      }),
    );
    let caught: unknown;
    try {
      await failed.runtime.signPreparedUserOperation(prepared(failed.runtime));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(OgpWebAuthnKernelOwnerError);
    expect(caught).toMatchObject({ code: "webauthn_kernel_owner_signing_failed" });
    expect(String((caught as Error).message)).not.toContain("provider secret material");
  });
});
