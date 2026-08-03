import { p256 } from "@noble/curves/nist.js";
import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import type { KernelValidator } from "@zerodev/sdk/types";
import {
  createPublicClient,
  custom,
  decodeAbiParameters,
  type Hex,
  hexToBytes,
  toHex,
  zeroAddress,
} from "viem";
import { generatePrivateKey, privateKeyToAccount, toAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import {
  createKernelOperator,
  createKernelOwner,
  KERNEL_RUNTIME_CAPABILITIES,
  type KernelSigner,
  type OgpKernelSignerError,
  toEcdsaKernelSigner,
  toP256KernelSigner,
  toWebAuthnKernelSigner,
} from "../src/index.js";

const chainId = 31_337;
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_ORDER = P256_ORDER / 2n;
const userOperation = {
  sender: `0x${"11".repeat(20)}` as const,
  nonce: 0n,
  callData: "0x" as const,
  callGasLimit: 300_000n,
  verificationGasLimit: 500_000n,
  preVerificationGas: 100_000n,
  maxFeePerGas: 2_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
  signature: "0x" as const,
};

function client() {
  return createPublicClient({
    transport: custom({
      async request({ method }) {
        if (method === "eth_chainId") return toHex(chainId);
        throw new Error(`unexpected RPC method ${method}`);
      },
    }),
  });
}

function p256Fixture(forceHighS = false) {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = toHex(p256.getPublicKey(privateKey, false));
  const requests: Readonly<{ hash: `0x${string}` }>[] = [];
  return {
    privateKey,
    publicKey,
    requests,
    signer: {
      publicKey,
      async signMessageHash(request: Readonly<{ hash: `0x${string}` }>) {
        requests.push(request);
        const signature = p256.sign(hexToBytes(request.hash), privateKey, {
          lowS: !forceHighS,
          prehash: false,
        });
        const s = forceHighS && !signature.hasHighS() ? P256_ORDER - signature.s : signature.s;
        return `0x${signature.r.toString(16).padStart(64, "0")}${s
          .toString(16)
          .padStart(64, "0")}` as const;
      },
    },
  };
}

function customKernelSigner(
  supportedKernelVersions = KERNEL_V3_3,
): KernelSigner<KernelValidator<"CustomValidator">> & { readonly name: string } {
  const account = toAccount({
    address: zeroAddress,
    async signMessage() {
      return "0x1234";
    },
    async signTransaction() {
      return "0x1234";
    },
    async signTypedData() {
      return "0x1234";
    },
  });
  return Object.freeze({
    name: "custom",
    async validator() {
      return {
        ...account,
        source: "CustomValidator" as const,
        supportedKernelVersions,
        validatorType: "SECONDARY" as const,
        getIdentifier: () => `0x${"12".repeat(20)}` as const,
        async getEnableData() {
          return "0x1234" as const;
        },
        async getNonceKey(_accountAddress?: `0x${string}`, customNonceKey?: bigint) {
          return customNonceKey ?? 0n;
        },
        async getStubSignature() {
          return "0x1234" as const;
        },
        async signUserOperation() {
          return "0x1234" as const;
        },
        async isEnabled() {
          return false;
        },
      };
    },
  });
}

describe("Kernel signer modules", () => {
  it("uses the same signer interface for ECDSA, WebAuthn, and raw P-256 in both roles", async () => {
    const ecdsa = privateKeyToAccount(generatePrivateKey());
    const webauthnKey = p256Fixture();
    const pubX = BigInt(`0x${webauthnKey.publicKey.slice(4, 68)}`);
    const pubY = BigInt(`0x${webauthnKey.publicKey.slice(68)}`);
    const signMessageCallback = vi.fn(async () => "0x1234" as Hex);
    const p256Key = p256Fixture();
    const ecdsaSigner = toEcdsaKernelSigner(ecdsa);
    const webauthnSigner = toWebAuthnKernelSigner({
      pubX,
      pubY,
      authenticatorId: "credential-id",
      authenticatorIdHash: `0x${"22".repeat(32)}`,
      rpID: "example.test",
      signMessageCallback,
    });
    const p256Signer = toP256KernelSigner(p256Key.signer);
    const signers: readonly KernelSigner[] = [ecdsaSigner, webauthnSigner, p256Signer];

    for (const createRole of [createKernelOwner, createKernelOperator] as const) {
      for (const signer of signers) {
        const validator = await createRole({ client: client(), signer });
        expect(validator).toMatchObject({
          validatorType: "SECONDARY",
          supportedKernelVersions: KERNEL_V3_3,
        });
        expect(typeof validator.getEnableData).toBe("function");
        expect(typeof validator.getIdentifier).toBe("function");
        expect(typeof validator.getNonceKey).toBe("function");
        expect(typeof validator.getStubSignature).toBe("function");
        expect(typeof validator.signUserOperation).toBe("function");
        expect(Object.isFrozen(validator)).toBe(true);
      }
    }

    const ecdsaValidator = await createKernelOwner({ client: client(), signer: ecdsaSigner });
    const webauthnValidator = await createKernelOperator({
      client: client(),
      signer: webauthnSigner,
    });
    const p256Validator = await createKernelOperator({ client: client(), signer: p256Signer });
    expect(await ecdsaValidator.getEnableData()).toBe(ecdsa.address);
    expect(await webauthnValidator.signUserOperation(userOperation)).toBe("0x1234");
    expect(signMessageCallback).toHaveBeenCalledTimes(1);
    expect(await p256Validator.getEnableData()).toHaveLength(130);
  });

  it("plugs any module with the shared signer interface into either Kernel role", async () => {
    const signer = customKernelSigner();
    const [owner, operator] = await Promise.all([
      createKernelOwner({ client: client(), signer }),
      createKernelOperator({ client: client(), signer }),
    ]);

    expect(owner.source).toBe("CustomValidator");
    expect(operator.source).toBe("CustomValidator");
    expect(owner.getIdentifier()).toBe(`0x${"12".repeat(20)}`);
    expect(operator.getIdentifier()).toBe(`0x${"12".repeat(20)}`);
  });

  it("rejects a module whose validator is not compatible with Kernel 3.3", async () => {
    await expect(
      createKernelOperator({ client: client(), signer: customKernelSigner("0.3.2") }),
    ).rejects.toMatchObject({
      code: "kernel_validator_incompatible",
    } satisfies Partial<OgpKernelSignerError>);
  });

  it("binds raw P-256 to leekt/P256Validator and its exact ABI", async () => {
    const fixture = p256Fixture(true);
    const validator = await createKernelOperator({
      client: client(),
      signer: toP256KernelSigner(fixture.signer),
    });
    const [x, y] = decodeAbiParameters(
      [
        { name: "x", type: "uint256" },
        { name: "y", type: "uint256" },
      ],
      await validator.getEnableData(),
    );
    const signature = await validator.signUserOperation(userOperation);
    const [r, s] = decodeAbiParameters(
      [
        { name: "r", type: "uint256" },
        { name: "s", type: "uint256" },
      ],
      signature,
    );

    expect(validator.source).toBe("P256Validator");
    expect(validator.getIdentifier()).toBe("0x9906ab44ff795883c5a725687a2705be4118b0f3");
    expect(validator.address.toLowerCase()).toBe(
      KERNEL_RUNTIME_CAPABILITIES.contracts.p256Validator.address.toLowerCase(),
    );
    expect(x).toBe(BigInt(`0x${fixture.publicKey.slice(4, 68)}`));
    expect(y).toBe(BigInt(`0x${fixture.publicKey.slice(68)}`));
    expect(r).toBeGreaterThan(0n);
    expect(s).toBeGreaterThan(0n);
    expect(s).toBeLessThanOrEqual(P256_HALF_ORDER);
    expect(fixture.requests).toHaveLength(1);
    expect(Object.isFrozen(fixture.requests[0])).toBe(true);
  });

  it("rejects a raw P-256 signature from a different key", async () => {
    const expected = p256Fixture();
    const substituted = p256Fixture();
    const validator = await createKernelOperator({
      client: client(),
      signer: toP256KernelSigner({
        publicKey: expected.publicKey,
        signMessageHash: substituted.signer.signMessageHash,
      }),
    });

    await expect(validator.signUserOperation(userOperation)).rejects.toMatchObject({
      code: "kernel_signing_failed",
    });
  });
});
