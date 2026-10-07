import { OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import { describe, expect, it } from "vitest";
import { createKmsSessionSignerProvider } from "../src/session-signer/kms-provider.js";
import { createMemorySessionSignerRegistry } from "../src/session-signer/registry.js";
import { createTestKms } from "./support.js";

const identity = { clientId: "app", subject: "user", deviceId: "device" };
const hash = `0x${"12".repeat(32)}` as const;
const unknownCredential = {
  version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  kind: "ecdsa" as const,
  address: `0x${"11".repeat(20)}` as const,
};

describe("retained hosted signer identity", () => {
  it("never creates custody while recovering or signing an absent binding", async () => {
    let encryptions = 0;
    const kms = createTestKms();
    const provider = createKmsSessionSignerProvider({
      providerId: "primary",
      registry: createMemorySessionSignerRegistry(),
      kms: {
        ...kms,
        async encrypt(value) {
          encryptions++;
          return kms.encrypt(value);
        },
      },
    });
    for (const request of [
      () => provider.credential({ ...identity, expectedCredential: unknownCredential }),
      () => provider.sign({ ...identity, expectedCredential: unknownCredential, hash }),
    ])
      await expect(request()).rejects.toMatchObject({ code: "session_signer_binding_unavailable" });
    expect(encryptions).toBe(0);
  });

  it("recovers one winning credential across independent providers and a lost creation reply", async () => {
    const registry = createMemorySessionSignerRegistry();
    const kms = createTestKms();
    let encryptions = 0;
    const options = {
      providerId: "primary",
      registry,
      kms: {
        ...kms,
        async encrypt(value: string) {
          encryptions++;
          return kms.encrypt(value);
        },
      },
    };
    const first = createKmsSessionSignerProvider(options);
    const second = createKmsSessionSignerProvider(options);
    const [credential, raced] = await Promise.all([
      first.createCredential(identity),
      second.createCredential(identity),
    ]);
    expect(raced).toEqual(credential);
    expect(encryptions).toBe(1);
    const recreated = createKmsSessionSignerProvider(options);
    expect(await recreated.createCredential(identity)).toEqual(credential);
    expect(await recreated.credential({ ...identity, expectedCredential: credential })).toEqual(
      credential,
    );
    const request = { ...identity, expectedCredential: credential, hash };
    expect((await recreated.sign(request)) === (await first.sign(request))).toBe(true);
    expect(encryptions).toBe(1);
  });

  it("releases failed creation without publishing a binding and never treats a read error as absence", async () => {
    const registry = createMemorySessionSignerRegistry();
    const kms = createTestKms();
    let fail = true;
    let encryptions = 0;
    const options = {
      providerId: "primary",
      registry,
      kms: {
        ...kms,
        async encrypt(value: string) {
          encryptions++;
          if (fail) throw new Error("seal unavailable");
          return kms.encrypt(value);
        },
      },
    };
    const provider = createKmsSessionSignerProvider(options);
    await expect(provider.createCredential(identity)).rejects.toMatchObject({
      code: "session_signer_custody_unavailable",
    });
    await expect(
      provider.credential({ ...identity, expectedCredential: unknownCredential }),
    ).rejects.toMatchObject({ code: "session_signer_binding_unavailable" });
    fail = false;
    const credential = await provider.createCredential(identity);
    const broken = createKmsSessionSignerProvider({
      ...options,
      registry: {
        ...registry,
        async read() {
          throw new Error("store unavailable");
        },
      },
    });
    await expect(
      broken.sign({ ...identity, expectedCredential: credential, hash }),
    ).rejects.toMatchObject({ code: "session_signer_registry_unavailable" });
    expect(encryptions).toBe(2);
  });

  it("refuses missing custody, decrypt failure and mismatched provider or public credential", async () => {
    const registry = createMemorySessionSignerRegistry();
    const kms = createTestKms();
    const options = { providerId: "primary", registry, kms };
    const original = createKmsSessionSignerProvider(options);
    const credential = await original.createCredential(identity);
    const request = { ...identity, expectedCredential: credential, hash };
    for (const provider of [
      createKmsSessionSignerProvider({
        ...options,
        kms: {
          ...kms,
          async decrypt() {
            return undefined;
          },
        },
      }),
      createKmsSessionSignerProvider({
        ...options,
        kms: {
          ...kms,
          async decrypt() {
            throw new Error("unavailable");
          },
        },
      }),
      createKmsSessionSignerProvider({ ...options, providerId: "another" }),
    ]) {
      await expect(provider.sign(request)).rejects.toMatchObject({ name: "SessionSignerError" });
      await expect(provider.createCredential(identity)).rejects.toMatchObject({
        name: "SessionSignerError",
      });
    }
    await expect(
      original.sign({ ...request, expectedCredential: unknownCredential }),
    ).rejects.toMatchObject({ code: "session_signer_binding_mismatch" });
    await expect(original.sign({ ...request, subject: "another" })).rejects.toMatchObject({
      code: "session_signer_binding_unavailable",
    });
    expect(await original.credential({ ...identity, expectedCredential: credential })).toEqual(
      credential,
    );
  });
});
