import { createWalletClient, custom, hashMessage } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { ecdsaWalletKey, kernelV33Deployment } from "../src/kernel.js";

const validator = kernelV33Deployment(143).ecdsaValidator;
const hash = `0x${"12".repeat(32)}` as const;

function fixture() {
  const owner = privateKeyToAccount(generatePrivateKey());
  const requests: { method: string; params: unknown }[] = [];
  const wallet = createWalletClient({
    account: owner.address,
    transport: custom({
      async request({ method, params }) {
        requests.push({ method, params });
        expect(method).toBe("personal_sign");
        expect(params).toEqual([hash, owner.address.toLowerCase()]);
        return owner.signMessage({ message: { raw: hash } });
      },
    }),
  });
  return { owner, wallet, requests };
}

describe("connected-wallet ECDSA key", () => {
  it("uses one viem personal_sign request and verifies the captured owner", async () => {
    const { owner, wallet, requests } = fixture();
    const key = ecdsaWalletKey({ wallet, validator });
    expect(requests).toEqual([]);
    expect(key.kind).toBe("ecdsa");
    expect(key.publicMaterial).toBe(owner.address.toLowerCase());
    const signature = await key.sign(hash);
    expect(await key.verify(hash, signature)).toBe(true);
    expect(await key.verify(hashMessage({ raw: hash }), signature)).toBe(false);
    expect(requests).toHaveLength(1);
  });

  it("rejects a disconnected wallet before any signing request", () => {
    expect(() =>
      ecdsaWalletKey({ wallet: { signMessage: async () => "0x" }, validator }),
    ).toThrowError(expect.objectContaining({ code: "kernel_runtime_input_invalid" }));
  });

  it.each(["other-owner", "raw-digest", "malformed"])(
    "rejects a %s signature locally",
    async (kind) => {
      const { owner } = fixture();
      const other = privateKeyToAccount(generatePrivateKey());
      const key = ecdsaWalletKey({
        wallet: {
          account: { address: owner.address },
          signMessage: async () =>
            kind === "malformed"
              ? "0x1234"
              : kind === "raw-digest"
                ? owner.sign({ hash })
                : other.signMessage({ message: { raw: hash } }),
        },
        validator,
      });
      await expect(key.sign(hash)).rejects.toMatchObject({
        code: "kernel_runtime_signature_invalid",
      });
    },
  );

  it("does not retry or retain wallet rejection text", async () => {
    const { owner } = fixture();
    let requests = 0;
    const key = ecdsaWalletKey({
      wallet: {
        account: { address: owner.address },
        signMessage: async () => {
          requests++;
          throw new Error("wallet-private-material");
        },
      },
      validator,
    });
    await expect(key.sign(hash)).rejects.toMatchObject({
      code: "kernel_runtime_signing_failed",
      message: "ECDSA key signing failed",
    });
    expect(requests).toBe(1);
  });
});
