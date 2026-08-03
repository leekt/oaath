import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { createEcdsaPermissionSignerRuntime } from "../src/index.js";

const adapterCalls = vi.hoisted(() => ({ signer: 0, signerId: 0 }));

vi.mock("@zerodev/permissions/signers", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@zerodev/permissions/signers")>()),
  async toECDSASigner() {
    adapterCalls.signer += 1;
    throw new Error("untrusted adapter output");
  },
  toSignerId() {
    adapterCalls.signerId += 1;
    throw new Error("untrusted adapter output");
  },
}));

describe("ECDSA permission signer adapter boundary", () => {
  it("does not admit ZeroDev adapter output into the production runtime", async () => {
    adapterCalls.signer = 0;
    adapterCalls.signerId = 0;
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
    const signature = await runtime.signMessageHash({ hash: `0x${"ab".repeat(32)}` });

    expect(signature).toMatch(/^0x[0-9a-f]{128}(?:1b|1c)$/u);
    expect(adapterCalls).toEqual({ signer: 0, signerId: 0 });
  });
});
