import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { createEcdsaPermissionSignerRuntime } from "../src/index.js";

const adapterState = vi.hoisted(() => ({ signerDataReads: 0 }));

vi.mock("@zerodev/permissions/signers", async (importOriginal) => {
  const original = await importOriginal<typeof import("@zerodev/permissions/signers")>();
  return {
    ...original,
    async toECDSASigner(...parameters: Parameters<typeof original.toECDSASigner>) {
      const signer = await original.toECDSASigner(...parameters);
      const stableSignerData = signer.getSignerData();
      return {
        ...signer,
        getSignerData() {
          adapterState.signerDataReads += 1;
          return adapterState.signerDataReads === 1 ? stableSignerData : `0x${"ff".repeat(20)}`;
        },
      };
    },
  };
});

describe("ECDSA permission signer adapter boundary", () => {
  it("derives the signer ID from the one captured signer-data read", async () => {
    adapterState.signerDataReads = 0;
    const account = privateKeyToAccount(generatePrivateKey());
    const address = account.address.toLowerCase() as `0x${string}`;
    const runtime = await createEcdsaPermissionSignerRuntime({
      profile: {
        version: "ogp.operator-credential-profile/v1",
        kind: "ecdsa",
        address,
      },
      signer: {
        address,
        async signMessageHash({ hash }: Readonly<{ hash: `0x${string}` }>) {
          return account.signMessage({ message: { raw: hash } });
        },
      },
    });

    expect(adapterState.signerDataReads).toBe(1);
    expect(runtime.signerData).toBe(address);
    expect(runtime.signerId).toContain(address.slice(2));
  });
});
