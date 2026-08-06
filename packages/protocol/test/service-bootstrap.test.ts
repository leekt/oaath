/**
 * The service bootstrap document: exact capture, canonical URLs, loopback
 * development exception, and the owner-validator/credential-kind agreement.
 *
 * @author taek <leekt216@gmail.com>
 */
import { describe, expect, it } from "vitest";
import {
  OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  OAATH_SERVICE_BOOTSTRAP_VERSION,
  parseIssuerIdentity,
  parseServiceBootstrap,
} from "../src/index.js";

const VALIDATOR = `0x${"22".repeat(20)}`;

function document(): Record<string, unknown> {
  return {
    version: OAATH_SERVICE_BOOTSTRAP_VERSION,
    application: {
      applicationId: "app-a",
      applicationName: "OAAth Example",
      clientId: "client-a",
      redirectUris: ["https://app.example/callback"],
    },
    userHandle: "user-1",
    account: {
      version: OAATH_KERNEL_ACCOUNT_PROFILE_VERSION,
      kind: "kernel",
      accountIndex: "0",
      kernelVersion: "0.4.0",
      factoryRoute: "kernel_factory",
      entryPoint: { version: "0.7" },
      ownerCredential: {
        version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
        kind: "ecdsa",
        address: `0x${"11".repeat(20)}`,
      },
    },
    ownerValidator: VALIDATOR,
    chains: [{ chainId: 31_337, usage: true, feePayer: null }],
  };
}

describe("service bootstrap", () => {
  it("captures the exact versioned document", () => {
    const bootstrap = parseServiceBootstrap(document());
    expect(bootstrap.application.clientId).toBe("client-a");
    expect(bootstrap.account.ownerCredential.kind).toBe("ecdsa");
    expect(bootstrap.ownerValidator).toBe(VALIDATOR);
    expect(bootstrap.chains).toEqual([{ chainId: 31_337, usage: true, feePayer: null }]);
    expect(Object.isFrozen(bootstrap)).toBe(true);
    expect(Object.isFrozen(bootstrap.chains)).toBe(true);
  });

  it("captures a fee payer snapshot exactly", () => {
    const bootstrap = parseServiceBootstrap({
      ...document(),
      chains: [
        {
          chainId: 1,
          usage: false,
          feePayer: { address: `0x${"77".repeat(20)}`, balance: "1000" },
        },
      ],
    });
    expect(bootstrap.chains[0]?.feePayer).toEqual({
      address: `0x${"77".repeat(20)}`,
      balance: "1000",
    });
  });

  it.each([
    ["a wrong version", { version: "oaath.service-bootstrap/v2" }],
    ["an unknown field", { extra: 1 }],
    ["a missing user handle", { userHandle: "" }],
    ["no chains", { chains: [] }],
    [
      "a repeated chain",
      {
        chains: [
          { chainId: 1, usage: false, feePayer: null },
          { chainId: 1, usage: true, feePayer: null },
        ],
      },
    ],
    [
      "a non-canonical redirect URI",
      (() => {
        const base = document();
        return {
          application: {
            ...(base.application as Record<string, unknown>),
            redirectUris: ["https://app.example/callback/"],
          },
        };
      })(),
    ],
    // The deployment fact and the credential kind must agree: an ecdsa owner
    // requires the caller-bound validator, any other kind must carry none.
    ["a missing ecdsa owner validator", { ownerValidator: null }],
  ] as const)("fails closed on %s", (_label, override) => {
    expect(() => parseServiceBootstrap({ ...document(), ...override })).toThrowError(
      expect.objectContaining({ code: "service_bootstrap_invalid" }),
    );
  });

  it("defaults absent session-signer custody to frontend and captures declared custody exactly", () => {
    // Absence means the one custody this document version ever implied.
    expect(parseServiceBootstrap(document()).sessionSigner).toEqual({
      mode: "frontend",
      providerId: null,
    });
    expect(
      parseServiceBootstrap({
        ...document(),
        sessionSigner: { mode: "frontend", providerId: null },
      }).sessionSigner,
    ).toEqual({ mode: "frontend", providerId: null });
    for (const mode of ["application_backend", "oaath_hosted"] as const) {
      const bootstrap = parseServiceBootstrap({
        ...document(),
        sessionSigner: { mode, providerId: "kms-primary" },
      });
      expect(bootstrap.sessionSigner).toEqual({ mode, providerId: "kms-primary" });
      expect(Object.isFrozen(bootstrap.sessionSigner)).toBe(true);
    }
  });

  it.each([
    // Custody modes are different trust models; an unknown one rejects the
    // whole document instead of composing a realm on a substituted model.
    [{ mode: "owner_hosted", providerId: "kms-primary" }],
    [{ mode: "frontend", providerId: "kms-primary" }],
    [{ mode: "oaath_hosted", providerId: null }],
    [{ mode: "oaath_hosted", providerId: "" }],
    [{ mode: "oaath_hosted" }],
    [{ mode: "oaath_hosted", providerId: "kms-primary", extra: true }],
    [null],
    ["frontend"],
  ])("refuses a malformed or unknown session-signer declaration", (sessionSigner) => {
    expect(() => parseServiceBootstrap({ ...document(), sessionSigner })).toThrowError(
      expect.objectContaining({ code: "service_bootstrap_invalid" }),
    );
  });

  it("refuses a stray owner validator for a non-ecdsa owner credential", () => {
    const base = document();
    const account = base.account as Record<string, unknown>;
    expect(() =>
      parseServiceBootstrap({
        ...base,
        account: {
          ...account,
          ownerCredential: {
            version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
            kind: "p256",
            publicKey:
              "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
          },
        },
        ownerValidator: VALIDATOR,
      }),
    ).toThrowError(expect.objectContaining({ code: "service_bootstrap_invalid" }));
  });
});

describe("loopback development URLs", () => {
  it.each(["http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"])(
    "accepts %s as a canonical issuer",
    (url) => {
      expect(parseIssuerIdentity({ version: "oaath.issuer/v1", url }).url).toBe(url);
    },
  );

  it("still refuses plaintext http on every non-loopback host", () => {
    for (const url of [
      "http://issuer.example",
      "http://192.168.1.10:8787",
      "http://localhost.evil.example",
      "http://[::2]:8787",
    ]) {
      expect(() => parseIssuerIdentity({ version: "oaath.issuer/v1", url })).toThrowError(
        expect.objectContaining({ code: "issuer_invalid" }),
      );
    }
  });
});
