import { readFile } from "node:fs/promises";
import { p256 } from "@noble/curves/nist.js";
import { hexToBytes, toHex } from "viem";
import { entryPoint07Address } from "viem/account-abstraction";
import { describe, expect, it, vi } from "vitest";
import {
  createP256KernelOwnerRuntime,
  getKernelRuntimeCapability,
  type KernelAccountProfile,
  OgpP256KernelOwnerError,
  type P256KernelOwnerRestorationReadRequest,
  type P256KernelOwnerRuntime,
  prepareUserOperation,
} from "../src/index.js";

const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const PRECOMPILE_SUCCESS = `0x${"00".repeat(31)}01` as const;
const otherAddress = `0x${"99".repeat(20)}` as const;

interface P256Fixture {
  p256Validator: {
    sourceCommit: string;
    runtimeKeccak256: `0x${string}`;
    runtimeByteLength: number;
    runtimeBytecode: `0x${string}`;
  };
}

const fixture = JSON.parse(
  await readFile(new URL("./fixtures/kernel-v3.3-bytecode.json", import.meta.url), "utf8"),
) as P256Fixture;

function profile(
  publicKey: `0x${string}`,
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
      kind: "p256",
      publicKey,
    },
  };
}

function signer(privateKey = p256.utils.randomPrivateKey(), forceHighS = false) {
  const publicKey = toHex(p256.getPublicKey(privateKey, false));
  let calls = 0;
  return {
    privateKey,
    publicKey,
    capability: {
      publicKey,
      async signMessageHash({ hash }: { hash: `0x${string}` }) {
        calls += 1;
        const signed = p256.sign(hexToBytes(hash), privateKey, {
          lowS: !forceHighS,
          prehash: false,
        });
        const s = forceHighS && !signed.hasHighS() ? P256_ORDER - signed.s : signed.s;
        return `0x${signed.r.toString(16).padStart(64, "0")}${s
          .toString(16)
          .padStart(64, "0")}` as const;
      },
    },
    calls: () => calls,
  };
}

function prepared(
  runtime: P256KernelOwnerRuntime,
  overrides: {
    chainId?: number;
    entryPoint?: `0x${string}`;
    sender?: `0x${string}`;
    factory?: { address: `0x${string}`; data: `0x${string}` } | null;
  } = {},
) {
  return prepareUserOperation({
    kind: "execution",
    grantId: "grant-p256-owner",
    chainId: overrides.chainId ?? runtime.action.chainId,
    entryPoint: {
      version: "0.7",
      address: overrides.entryPoint ?? (entryPoint07Address.toLowerCase() as `0x${string}`),
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

async function ownerRuntime(
  owner = signer(),
  options: {
    chainId?: number;
    accountIndex?: string;
    factoryRoute?: "kernel_factory" | "meta_factory";
  } = {},
) {
  return {
    owner,
    runtime: await createP256KernelOwnerRuntime({
      profile: profile(owner.publicKey, options),
      chainId: options.chainId ?? 31_337,
      signer: owner.capability,
    }),
  };
}

function restorationReader(
  runtime: P256KernelOwnerRuntime,
  publicKey: `0x${string}`,
  accountCode: `0x${string}`,
  requests: P256KernelOwnerRestorationReadRequest[] = [],
) {
  return {
    requests,
    capability: {
      async read(request: P256KernelOwnerRestorationReadRequest) {
        requests.push(request);
        if (request.type === "chain_id") return runtime.action.chainId;
        if (request.type === "p256_validator_code") {
          return fixture.p256Validator.runtimeBytecode;
        }
        if (request.type === "p256_precompile") return PRECOMPILE_SUCCESS;
        if (request.type === "account_code") return accountCode;
        if (request.type === "kernel_root_validator") {
          return `0x01${runtime.validatorAddress.slice(2)}`;
        }
        return publicKey;
      },
    },
  };
}

async function expectCode(action: () => Promise<unknown>, code: string): Promise<void> {
  await expect(action()).rejects.toMatchObject({ code });
}

describe("P-256 Kernel owner runtime", () => {
  it("pins P256Validator and derives one chain-independent Kernel 3.3 identity", async () => {
    const owner = signer();
    const direct = await ownerRuntime(owner, {
      chainId: 31_337,
      accountIndex: "17",
      factoryRoute: "kernel_factory",
    });
    const recreated = await ownerRuntime(signer(owner.privateKey), {
      chainId: 31_337,
      accountIndex: "17",
      factoryRoute: "kernel_factory",
    });
    const meta = await ownerRuntime(signer(owner.privateKey), {
      chainId: 31_337,
      accountIndex: "17",
      factoryRoute: "meta_factory",
    });
    const laterChain = await ownerRuntime(signer(owner.privateKey), {
      chainId: 1_000_001,
      accountIndex: "17",
      factoryRoute: "kernel_factory",
    });

    expect(getKernelRuntimeCapability("owner_p256")).toEqual({
      status: "available",
      anchors: [
        "leekt_p256_validator.P256Validator",
        "ogp.createP256KernelOwnerRuntime",
        "zerodev_sdk.createKernelAccount",
        "zerodev_sdk.KERNEL_V3_3",
        "kernel.v3_3",
        "entrypoint.v0_7",
      ],
      constraints: ["action_runtime_and_precompile_evidence_required"],
    });
    expect(fixture.p256Validator).toMatchObject({
      sourceCommit: "8f6a71992e297f2e7caa61df2c6eb0b6d9145d2d",
      runtimeKeccak256: "0xd7d9a5b1ddd1e22e7235268fd624c7c0714e5046b199d507bbfe5e03408e579d",
      runtimeByteLength: 1919,
    });
    expect(direct.runtime.validatorAddress).toBe("0x9906ab44ff795883c5a725687a2705be4118b0f3");
    expect(direct.runtime.accountAddress).toBe(recreated.runtime.accountAddress);
    expect(meta.runtime.accountAddress).toBe(direct.runtime.accountAddress);
    expect(laterChain.runtime.accountAddress).toBe(direct.runtime.accountAddress);
    expect(direct.runtime.factory.address).toBe("0x2577507b78c2008ff367261cb6285d44ba5ef2e9");
    expect(meta.runtime.factory.address).toBe("0xd703aae79538628d27099b8c4f621be4ccd142d5");
    expect(direct.runtime.factory).not.toEqual(meta.runtime.factory);
    expect(direct.runtime.enableData).toHaveLength(130);
    expect(direct.runtime.action).toMatchObject({
      chainId: 31_337,
      accountIndex: "17",
      kernelVersion: "0.3.3",
      entryPointVersion: "0.7",
      ownerCredential: { kind: "p256", publicKey: owner.publicKey },
    });
    expect(Object.isFrozen(direct.runtime)).toBe(true);
    expect(Object.isFrozen(direct.runtime.factory)).toBe(true);
    expect(owner.calls()).toBe(0);
  });

  it("verifies the substrate before counterfactual signing and normalizes high-S", async () => {
    const current = await ownerRuntime(signer(undefined, true));
    await expectCode(
      () => current.runtime.signPreparedUserOperation(prepared(current.runtime)),
      "p256_kernel_owner_restoration_required",
    );
    expect(current.owner.calls()).toBe(0);

    const reads = restorationReader(current.runtime, current.owner.publicKey, "0x");
    await expect(current.runtime.restore(reads.capability)).resolves.toEqual({
      status: "counterfactual",
      chainId: 31_337,
      account: current.runtime.accountAddress,
      validator: current.runtime.validatorAddress,
      publicKey: current.owner.publicKey,
    });
    expect(reads.requests.map(({ type }) => type)).toEqual([
      "chain_id",
      "p256_validator_code",
      "p256_precompile",
      "account_code",
    ]);
    expect(reads.requests.every(Object.isFrozen)).toBe(true);

    const operation = prepared(current.runtime);
    const signature = await current.runtime.signPreparedUserOperation(operation);
    const s = BigInt(`0x${signature.slice(66)}`);
    expect(signature).toMatch(/^0x[0-9a-f]{128}$/u);
    expect(s).toBeLessThanOrEqual(P256_ORDER / 2n);
    expect(
      p256.verify(
        hexToBytes(signature),
        hexToBytes(operation.userOperationHash),
        hexToBytes(current.owner.publicKey),
        { format: "compact", lowS: true, prehash: false },
      ),
    ).toBe(true);
    expect(current.owner.calls()).toBe(1);
  });

  it("requires exact deployed root and stored-key evidence for factory-free signing", async () => {
    const current = await ownerRuntime();
    const operation = prepared(current.runtime, { factory: null });
    await expectCode(
      () => current.runtime.signPreparedUserOperation(operation),
      "p256_kernel_owner_restoration_required",
    );

    const reads = restorationReader(current.runtime, current.owner.publicKey, "0x6000");
    await expect(current.runtime.restore(reads.capability)).resolves.toEqual({
      status: "deployed",
      chainId: 31_337,
      account: current.runtime.accountAddress,
      validator: current.runtime.validatorAddress,
      publicKey: current.owner.publicKey,
    });
    expect(reads.requests.map(({ type }) => type)).toEqual([
      "chain_id",
      "p256_validator_code",
      "p256_precompile",
      "account_code",
      "kernel_root_validator",
      "p256_validator_public_key",
    ]);
    await current.runtime.signPreparedUserOperation(operation);
    expect(current.owner.calls()).toBe(1);

    await expectCode(
      () => current.runtime.restore({ read: async () => 31_337, extra: true }),
      "p256_kernel_owner_restoration_unreadable",
    );
    await expectCode(
      () => current.runtime.signPreparedUserOperation(operation),
      "p256_kernel_owner_restoration_required",
    );
    expect(current.owner.calls()).toBe(1);
  });

  it("distinguishes missing, unreadable, and mismatched substrate and owner evidence", async () => {
    const cases: readonly [
      string,
      (
        request: P256KernelOwnerRestorationReadRequest,
        current: Awaited<ReturnType<typeof ownerRuntime>>,
      ) => unknown,
      string,
    ][] = [
      [
        "unavailable",
        () => Promise.reject(new Error("provider secret")),
        "p256_kernel_owner_restoration_unavailable",
      ],
      ["unreadable chain", () => "0x7a69", "p256_kernel_owner_restoration_unreadable"],
      [
        "wrong chain",
        (request) => (request.type === "chain_id" ? 31_338 : "0x"),
        "p256_kernel_owner_binding_mismatch",
      ],
      [
        "validator absent",
        (request) => (request.type === "chain_id" ? 31_337 : "0x"),
        "p256_kernel_owner_restoration_absent",
      ],
      [
        "validator unreadable",
        (request) => (request.type === "chain_id" ? 31_337 : "0x0"),
        "p256_kernel_owner_restoration_unreadable",
      ],
      [
        "validator mismatch",
        (request) => {
          if (request.type === "chain_id") return 31_337;
          return `0x${"00".repeat(1919)}`;
        },
        "p256_kernel_owner_binding_mismatch",
      ],
      [
        "precompile absent",
        (request) => {
          if (request.type === "chain_id") return 31_337;
          if (request.type === "p256_validator_code") return fixture.p256Validator.runtimeBytecode;
          return `0x${"00".repeat(32)}`;
        },
        "p256_kernel_owner_restoration_absent",
      ],
      [
        "precompile unreadable",
        (request) => {
          if (request.type === "chain_id") return 31_337;
          if (request.type === "p256_validator_code") return fixture.p256Validator.runtimeBytecode;
          return "0x01";
        },
        "p256_kernel_owner_restoration_unreadable",
      ],
      [
        "account unreadable",
        (request) => {
          if (request.type === "chain_id") return 31_337;
          if (request.type === "p256_validator_code") return fixture.p256Validator.runtimeBytecode;
          if (request.type === "p256_precompile") return PRECOMPILE_SUCCESS;
          return "0x0";
        },
        "p256_kernel_owner_restoration_unreadable",
      ],
      [
        "root mismatch",
        (request) => {
          if (request.type === "chain_id") return 31_337;
          if (request.type === "p256_validator_code") return fixture.p256Validator.runtimeBytecode;
          if (request.type === "p256_precompile") return PRECOMPILE_SUCCESS;
          if (request.type === "account_code") return "0x60";
          return `0x01${otherAddress.slice(2)}`;
        },
        "p256_kernel_owner_binding_mismatch",
      ],
      [
        "key mismatch",
        (request, current) => {
          if (request.type === "chain_id") return 31_337;
          if (request.type === "p256_validator_code") return fixture.p256Validator.runtimeBytecode;
          if (request.type === "p256_precompile") return PRECOMPILE_SUCCESS;
          if (request.type === "account_code") return "0x60";
          if (request.type === "kernel_root_validator") {
            return `0x01${current.runtime.validatorAddress.slice(2)}`;
          }
          return signer().publicKey;
        },
        "p256_kernel_owner_binding_mismatch",
      ],
      [
        "key unreadable",
        (request, current) => {
          if (request.type === "chain_id") return 31_337;
          if (request.type === "p256_validator_code") return fixture.p256Validator.runtimeBytecode;
          if (request.type === "p256_precompile") return PRECOMPILE_SUCCESS;
          if (request.type === "account_code") return "0x60";
          if (request.type === "kernel_root_validator") {
            return `0x01${current.runtime.validatorAddress.slice(2)}`;
          }
          return "0x04";
        },
        "p256_kernel_owner_restoration_unreadable",
      ],
    ];

    for (const [, response, code] of cases) {
      const current = await ownerRuntime();
      await expectCode(
        () =>
          current.runtime.restore({
            async read(request: P256KernelOwnerRestorationReadRequest) {
              return response(request, current);
            },
          }),
        code,
      );
      await expectCode(
        () => current.runtime.signPreparedUserOperation(prepared(current.runtime)),
        "p256_kernel_owner_restoration_required",
      );
      expect(current.owner.calls()).toBe(0);
    }
  });

  it("rejects profile, action, and prepared-operation substitutions before signing", async () => {
    const owner = signer();
    const current = await ownerRuntime(owner);
    const wrong = signer();
    await expectCode(
      () =>
        createP256KernelOwnerRuntime({
          profile: profile(owner.publicKey),
          chainId: 31_337,
          signer: wrong.capability,
        }),
      "p256_kernel_owner_binding_mismatch",
    );
    await expectCode(
      () =>
        createP256KernelOwnerRuntime({
          profile: {
            ...profile(owner.publicKey),
            ownerCredential: {
              version: "ogp.owner-credential-profile/v1",
              kind: "ecdsa",
              address: otherAddress,
            },
          },
          chainId: 31_337,
          signer: owner.capability,
        }),
      "p256_kernel_owner_input_invalid",
    );

    const reads = restorationReader(current.runtime, owner.publicKey, "0x");
    await current.runtime.restore(reads.capability);
    for (const substitute of [
      prepared(current.runtime, { chainId: 31_338 }),
      prepared(current.runtime, { entryPoint: otherAddress }),
      prepared(current.runtime, { sender: otherAddress }),
      prepared(current.runtime, { factory: { ...current.runtime.factory, address: otherAddress } }),
      prepared(current.runtime, { factory: { ...current.runtime.factory, data: "0x00" } }),
    ]) {
      await expectCode(
        () => current.runtime.signPreparedUserOperation(substitute),
        "p256_kernel_owner_binding_mismatch",
      );
    }
    await expectCode(
      () =>
        current.runtime.signPreparedUserOperation({ ...prepared(current.runtime), extra: true }),
      "p256_kernel_owner_prepared_operation_invalid",
    );
    expect(owner.calls()).toBe(0);
  });

  it("captures capabilities once and rejects hostile inputs and invalid signatures", async () => {
    const owner = signer();
    const mutableProfile = profile(owner.publicKey);
    const mutableSigner: {
      publicKey: `0x${string}`;
      signMessageHash: (request: { hash: `0x${string}` }) => Promise<unknown>;
    } = { ...owner.capability };
    const current = await createP256KernelOwnerRuntime({
      profile: mutableProfile,
      chainId: 31_337,
      signer: mutableSigner,
    });
    Reflect.set(mutableProfile, "accountIndex", "999");
    mutableSigner.publicKey = signer().publicKey;
    mutableSigner.signMessageHash = async () => "0x";
    await current.restore(restorationReader(current, owner.publicKey, "0x").capability);
    await current.signPreparedUserOperation(prepared(current));
    expect(owner.calls()).toBe(1);

    const accessor = Object.defineProperty({}, "publicKey", {
      enumerable: true,
      get: vi.fn(() => owner.publicKey),
    });
    Object.defineProperty(accessor, "signMessageHash", {
      enumerable: true,
      value: owner.capability.signMessageHash,
    });
    for (const hostile of [
      accessor,
      { ...owner.capability, extra: true },
      Object.assign(Object.create({ inherited: true }), owner.capability),
      Object.assign({ ...owner.capability }, { [Symbol("secret")]: true }),
      new Proxy(
        {},
        {
          getPrototypeOf: () => {
            throw new Error("signer secret");
          },
        },
      ),
    ]) {
      await expectCode(
        () =>
          createP256KernelOwnerRuntime({
            profile: profile(owner.publicKey),
            chainId: 31_337,
            signer: hostile,
          }),
        "p256_kernel_owner_signer_invalid",
      );
    }

    const wrong = signer();
    for (const signMessageHash of [
      async () => "0x",
      async () => `0x${"00".repeat(64)}`,
      wrong.capability.signMessageHash,
      async () => {
        throw new Error("provider secret");
      },
    ]) {
      const failed = await createP256KernelOwnerRuntime({
        profile: profile(owner.publicKey),
        chainId: 31_337,
        signer: { publicKey: owner.publicKey, signMessageHash },
      });
      await failed.restore(restorationReader(failed, owner.publicKey, "0x").capability);
      let caught: unknown;
      try {
        await failed.signPreparedUserOperation(prepared(failed));
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(OgpP256KernelOwnerError);
      expect(caught).toMatchObject({ code: "p256_kernel_owner_signing_failed" });
      expect(String((caught as Error).message)).not.toContain("provider secret");
    }
  });

  it("rejects malformed top-level and restoration capabilities", async () => {
    const owner = signer();
    for (const value of [
      { profile: profile(owner.publicKey), chainId: 0, signer: owner.capability },
      { profile: profile(owner.publicKey), chainId: 31_337, signer: owner.capability, extra: true },
      new Proxy(
        {},
        {
          getPrototypeOf: () => {
            throw new Error("input secret");
          },
        },
      ),
    ]) {
      await expectCode(
        () => createP256KernelOwnerRuntime(value),
        "p256_kernel_owner_input_invalid",
      );
    }
    const current = await ownerRuntime(owner);
    await expectCode(
      () => current.runtime.restore({ read: async () => 31_337, extra: true }),
      "p256_kernel_owner_restoration_unreadable",
    );
    await expectCode(
      () =>
        current.runtime.restore(
          new Proxy(
            {},
            {
              ownKeys: () => {
                throw new Error("secret");
              },
            },
          ),
        ),
      "p256_kernel_owner_restoration_unreadable",
    );
  });
});
