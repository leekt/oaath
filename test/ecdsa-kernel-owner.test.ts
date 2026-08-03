import fc from "fast-check";
import { recoverMessageAddress } from "viem";
import { entryPoint07Address } from "viem/account-abstraction";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import {
  createEcdsaKernelOwnerRuntime,
  type EcdsaKernelOwnerRuntime,
  getKernelRuntimeCapability,
  type KernelAccountProfile,
  OgpEcdsaKernelOwnerError,
  prepareUserOperation,
} from "../src/index.js";

const otherAddress = `0x${"99".repeat(20)}` as const;

function lower(value: string): `0x${string}` {
  return value.toLowerCase() as `0x${string}`;
}

function profile(
  owner: `0x${string}`,
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
      kind: "ecdsa",
      address: owner,
    },
  };
}

function signer(privateKey = generatePrivateKey()) {
  const account = privateKeyToAccount(privateKey);
  let calls = 0;
  return {
    privateKey,
    address: lower(account.address),
    capability: {
      address: lower(account.address),
      async signMessageHash({ hash }: { hash: `0x${string}` }) {
        calls += 1;
        return account.signMessage({ message: { raw: hash } });
      },
    },
    calls: () => calls,
  };
}

function prepared(
  runtime: EcdsaKernelOwnerRuntime,
  overrides: {
    chainId?: number;
    entryPoint?: `0x${string}`;
    sender?: `0x${string}`;
    factory?: { address: `0x${string}`; data: `0x${string}` } | null;
  } = {},
) {
  return prepareUserOperation({
    kind: "execution",
    grantId: "grant-ecdsa-owner",
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
  owner = signer(),
  options: {
    chainId?: number;
    accountIndex?: string;
    factoryRoute?: "kernel_factory" | "meta_factory";
  } = {},
) {
  return {
    owner,
    runtime: await createEcdsaKernelOwnerRuntime({
      profile: profile(owner.address, options),
      chainId: options.chainId ?? 31_337,
      signer: owner.capability,
    }),
  };
}

async function expectCodeAsync(action: () => Promise<unknown>, code: string) {
  await expect(action()).rejects.toMatchObject({ code });
}

describe("ECDSA Kernel owner runtime", () => {
  it("derives, recreates, and signs one exact ECDSA Kernel owner", async () => {
    const owner = signer();
    const direct = await runtime(owner, {
      chainId: 31_337,
      accountIndex: "17",
      factoryRoute: "kernel_factory",
    });
    const recreated = await runtime(signer(owner.privateKey), {
      chainId: 31_337,
      accountIndex: "17",
      factoryRoute: "kernel_factory",
    });
    const meta = await runtime(signer(owner.privateKey), {
      chainId: 31_337,
      accountIndex: "17",
      factoryRoute: "meta_factory",
    });
    const laterChain = await runtime(signer(owner.privateKey), {
      chainId: 1_000_001,
      accountIndex: "17",
      factoryRoute: "kernel_factory",
    });

    expect(getKernelRuntimeCapability("owner_ecdsa")).toMatchObject({
      status: "available",
    });
    expect(direct.runtime.accountAddress).toBe(recreated.runtime.accountAddress);
    expect(meta.runtime.accountAddress).toBe(direct.runtime.accountAddress);
    expect(laterChain.runtime.accountAddress).toBe(direct.runtime.accountAddress);
    expect(direct.runtime.factory.address).toBe("0x2577507b78c2008ff367261cb6285d44ba5ef2e9");
    expect(meta.runtime.factory.address).toBe("0xd703aae79538628d27099b8c4f621be4ccd142d5");
    expect(direct.runtime.factory).not.toEqual(meta.runtime.factory);
    expect(direct.runtime.validatorAddress).toBe("0x845adb2c711129d4f3966735ed98a9f09fc4ce57");
    expect(direct.runtime.action).toMatchObject({
      chainId: 31_337,
      accountIndex: "17",
      factoryRoute: "kernel_factory",
      ownerCredential: { kind: "ecdsa", address: owner.address },
    });
    expect(Object.isFrozen(direct.runtime)).toBe(true);
    expect(Object.isFrozen(direct.runtime.factory)).toBe(true);
    expect(owner.calls()).toBe(0);

    const operation = prepared(direct.runtime);
    const signature = await direct.runtime.signPreparedUserOperation(operation);
    expect(signature).toMatch(/^0x[0-9a-f]{130}$/u);
    expect(
      lower(
        await recoverMessageAddress({
          message: { raw: operation.userOperationHash },
          signature,
        }),
      ),
    ).toBe(owner.address);
    expect(owner.calls()).toBe(1);
  });

  it("keeps derivation deterministic for generated action identities", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 1, max: 1_000_000 }),
        fc.bigInt({ min: 0n, max: 1_000_000n }),
        fc.constantFrom("kernel_factory" as const, "meta_factory" as const),
        async (chainId, accountIndex, factoryRoute) => {
          const owner = signer();
          const first = await runtime(owner, {
            chainId,
            accountIndex: accountIndex.toString(10),
            factoryRoute,
          });
          const second = await runtime(signer(owner.privateKey), {
            chainId,
            accountIndex: accountIndex.toString(10),
            factoryRoute,
          });
          expect(second.runtime.accountAddress).toBe(first.runtime.accountAddress);
          expect(second.runtime.factory).toEqual(first.runtime.factory);
          expect(owner.calls()).toBe(0);
        },
      ),
      { numRuns: 24 },
    );
  });

  it("requires exact deployed owner evidence before restored signing", async () => {
    const current = await runtime();
    const operation = prepared(current.runtime, { factory: null });
    await expectCodeAsync(
      () => current.runtime.signPreparedUserOperation(operation),
      "ecdsa_kernel_owner_restoration_required",
    );
    expect(current.owner.calls()).toBe(0);

    const requests: unknown[] = [];
    const restored = await current.runtime.restore({
      async read(request: { type: string }) {
        requests.push(request);
        if (request.type === "chain_id") return 31_337;
        if (request.type === "account_code") return "0x6000";
        if (request.type === "kernel_root_validator") {
          return `0x01${current.runtime.validatorAddress.slice(2)}`;
        }
        if (request.type === "ecdsa_validator_owner") return current.owner.address;
        throw new Error("unexpected request");
      },
    });
    expect(restored).toEqual({
      status: "deployed",
      chainId: 31_337,
      account: current.runtime.accountAddress,
      validator: current.runtime.validatorAddress,
      owner: current.owner.address,
    });
    expect(requests).toEqual([
      { type: "chain_id", chainId: 31_337 },
      { type: "account_code", chainId: 31_337, account: current.runtime.accountAddress },
      {
        type: "kernel_root_validator",
        chainId: 31_337,
        account: current.runtime.accountAddress,
      },
      {
        type: "ecdsa_validator_owner",
        chainId: 31_337,
        validator: current.runtime.validatorAddress,
        account: current.runtime.accountAddress,
      },
    ]);
    expect(requests.every(Object.isFrozen)).toBe(true);
    await current.runtime.signPreparedUserOperation(operation);
    expect(current.owner.calls()).toBe(1);
  });

  it("distinguishes absent, unavailable, unreadable, and mismatched restoration", async () => {
    const cases: readonly [
      string,
      (type: string, current: Awaited<ReturnType<typeof runtime>>) => unknown,
      string,
    ][] = [
      [
        "unavailable",
        () => Promise.reject(new Error("provider secret")),
        "ecdsa_kernel_owner_restoration_unavailable",
      ],
      ["unreadable chain", () => "0x7a69", "ecdsa_kernel_owner_restoration_unreadable"],
      [
        "wrong chain",
        (type) => (type === "chain_id" ? 31_338 : "0x"),
        "ecdsa_kernel_owner_binding_mismatch",
      ],
      [
        "absent code",
        (type) => (type === "chain_id" ? 31_337 : "0x"),
        "ecdsa_kernel_owner_restoration_absent",
      ],
      [
        "unreadable code",
        (type) => (type === "chain_id" ? 31_337 : "0x0"),
        "ecdsa_kernel_owner_restoration_unreadable",
      ],
      [
        "wrong root",
        (type, current) => {
          if (type === "chain_id") return 31_337;
          if (type === "account_code") return "0x60";
          if (type === "kernel_root_validator") return `0x01${otherAddress.slice(2)}`;
          return current.owner.address;
        },
        "ecdsa_kernel_owner_binding_mismatch",
      ],
      [
        "unreadable root",
        (type) => {
          if (type === "chain_id") return 31_337;
          if (type === "account_code") return "0x60";
          return "0x01";
        },
        "ecdsa_kernel_owner_restoration_unreadable",
      ],
      [
        "wrong owner",
        (type, current) => {
          if (type === "chain_id") return 31_337;
          if (type === "account_code") return "0x60";
          if (type === "kernel_root_validator") {
            return `0x01${current.runtime.validatorAddress.slice(2)}`;
          }
          return otherAddress;
        },
        "ecdsa_kernel_owner_binding_mismatch",
      ],
      [
        "unreadable owner",
        (type, current) => {
          if (type === "chain_id") return 31_337;
          if (type === "account_code") return "0x60";
          if (type === "kernel_root_validator") {
            return `0x01${current.runtime.validatorAddress.slice(2)}`;
          }
          return "0x0";
        },
        "ecdsa_kernel_owner_restoration_unreadable",
      ],
    ];

    for (const [, response, code] of cases) {
      const current = await runtime();
      await expectCodeAsync(
        () =>
          current.runtime.restore({
            async read(request: { type: string }) {
              return response(request.type, current);
            },
          }),
        code,
      );
      await expectCodeAsync(
        () =>
          current.runtime.signPreparedUserOperation(prepared(current.runtime, { factory: null })),
        "ecdsa_kernel_owner_restoration_required",
      );
      expect(current.owner.calls()).toBe(0);
    }
  });

  it("rejects profile and prepared-operation substitutions before signing", async () => {
    const owner = signer();
    const current = await runtime(owner);
    const wrongSigner = signer();
    await expectCodeAsync(
      () =>
        createEcdsaKernelOwnerRuntime({
          profile: profile(current.owner.address),
          chainId: 31_337,
          signer: wrongSigner.capability,
        }),
      "ecdsa_kernel_owner_binding_mismatch",
    );
    expect(wrongSigner.calls()).toBe(0);
    await expectCodeAsync(
      () =>
        createEcdsaKernelOwnerRuntime({
          profile: {
            ...profile(current.owner.address),
            ownerCredential: {
              version: "ogp.owner-credential-profile/v1",
              kind: "p256",
              publicKey:
                "0x04b106b82180b6173f7b4b1dc51035ae4cdfa283c9c3e5e6f0a85a02fd602d4fcb3b846d1940ff729d5d8cf410f495e362f7acb3c0c233f5d803d854ff247c3ee1",
            },
          },
          chainId: 31_337,
          signer: current.owner.capability,
        }),
      "ecdsa_kernel_owner_input_invalid",
    );

    const profileSubstitutes = [
      await runtime(owner, { accountIndex: "1" }),
      await runtime(owner, { factoryRoute: "meta_factory" }),
      await runtime(owner, { chainId: 31_338 }),
    ];
    const currentOperation = prepared(current.runtime);
    for (const substitute of profileSubstitutes) {
      await expectCodeAsync(
        () => substitute.runtime.signPreparedUserOperation(currentOperation),
        "ecdsa_kernel_owner_binding_mismatch",
      );
    }

    const substitutes = [
      prepared(current.runtime, { chainId: 31_338 }),
      prepared(current.runtime, { entryPoint: `0x${"11".repeat(20)}` }),
      prepared(current.runtime, { sender: otherAddress }),
      prepared(current.runtime, {
        factory: { ...current.runtime.factory, address: otherAddress },
      }),
      prepared(current.runtime, {
        factory: { ...current.runtime.factory, data: "0x00" },
      }),
    ];
    for (const substitute of substitutes) {
      await expectCodeAsync(
        () => current.runtime.signPreparedUserOperation(substitute),
        "ecdsa_kernel_owner_binding_mismatch",
      );
    }
    expect(owner.calls()).toBe(0);

    await expectCodeAsync(
      () =>
        current.runtime.signPreparedUserOperation({ ...prepared(current.runtime), extra: true }),
      "ecdsa_kernel_owner_prepared_operation_invalid",
    );
    expect(owner.calls()).toBe(0);
  });

  it("captures hostile capabilities once and rejects invalid signatures", async () => {
    const owner = signer();
    const mutableProfile = profile(owner.address);
    const mutableSigner = { ...owner.capability };
    const captured = await createEcdsaKernelOwnerRuntime({
      profile: mutableProfile,
      chainId: 31_337,
      signer: mutableSigner,
    });
    Reflect.set(mutableProfile, "accountIndex", "999");
    Reflect.set(mutableProfile.ownerCredential, "address", otherAddress);
    mutableSigner.address = otherAddress;
    mutableSigner.signMessageHash = async () => {
      throw new Error("mutated signer");
    };
    expect(captured.action.accountIndex).toBe("0");
    expect(captured.action.ownerCredential).toMatchObject({ address: owner.address });
    await captured.signPreparedUserOperation(prepared(captured));
    expect(owner.calls()).toBe(1);

    const accessor = Object.defineProperty({}, "address", {
      enumerable: true,
      get: vi.fn(() => owner.address),
    });
    Object.defineProperty(accessor, "signMessageHash", {
      enumerable: true,
      value: owner.capability.signMessageHash,
    });
    await expectCodeAsync(
      () =>
        createEcdsaKernelOwnerRuntime({
          profile: profile(owner.address),
          chainId: 31_337,
          signer: accessor,
        }),
      "ecdsa_kernel_owner_signer_invalid",
    );

    for (const hostile of [
      { ...owner.capability, extra: true },
      Object.assign(Object.create({ inherited: true }), owner.capability),
      Object.assign({ ...owner.capability }, { [Symbol("secret")]: true }),
      new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error("signer secret");
          },
        },
      ),
    ]) {
      await expectCodeAsync(
        () =>
          createEcdsaKernelOwnerRuntime({
            profile: profile(owner.address),
            chainId: 31_337,
            signer: hostile,
          }),
        "ecdsa_kernel_owner_signer_invalid",
      );
    }

    const wrong = signer();
    const failures = [
      async () => "0x",
      async ({ hash }: { hash: `0x${string}` }) =>
        privateKeyToAccount(wrong.privateKey).signMessage({ message: { raw: hash } }),
      async () => {
        throw new Error("provider secret");
      },
    ];
    for (const signMessageHash of failures) {
      const failed = await createEcdsaKernelOwnerRuntime({
        profile: profile(owner.address),
        chainId: 31_337,
        signer: { address: owner.address, signMessageHash },
      });
      let caught: unknown;
      try {
        await failed.signPreparedUserOperation(prepared(failed));
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(OgpEcdsaKernelOwnerError);
      expect(caught).toMatchObject({ code: "ecdsa_kernel_owner_signing_failed" });
      expect(String((caught as Error).message)).not.toContain("provider secret");
    }
  });

  it("rejects malformed top-level inputs and restoration capabilities", async () => {
    const owner = signer();
    await expectCodeAsync(
      () =>
        createEcdsaKernelOwnerRuntime({
          profile: profile(owner.address),
          chainId: 0,
          signer: owner.capability,
        }),
      "ecdsa_kernel_owner_input_invalid",
    );
    await expectCodeAsync(
      () =>
        createEcdsaKernelOwnerRuntime({
          profile: profile(owner.address),
          chainId: 31_337,
          signer: owner.capability,
          extra: true,
        }),
      "ecdsa_kernel_owner_input_invalid",
    );
    await expectCodeAsync(
      () =>
        createEcdsaKernelOwnerRuntime(
          new Proxy(
            {},
            {
              getPrototypeOf() {
                throw new Error("input secret");
              },
            },
          ),
        ),
      "ecdsa_kernel_owner_input_invalid",
    );
    const current = await runtime(owner);
    await expectCodeAsync(
      () => current.runtime.restore({ read: async () => 31_337, extra: true }),
      "ecdsa_kernel_owner_restoration_unreadable",
    );
    await expectCodeAsync(
      () =>
        current.runtime.restore(
          new Proxy(
            {},
            {
              ownKeys() {
                throw new Error("reader secret");
              },
            },
          ),
        ),
      "ecdsa_kernel_owner_restoration_unreadable",
    );
  });
});
