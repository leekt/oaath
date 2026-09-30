import { OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import { hexToBytes, keccak256, sha256, stringToBytes, toHex } from "viem";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { enrolWebAuthnCredential, kernelKey } from "../src/kernel.js";

const rpId = "example.com";
const origin = "https://wallet.example.com";
const rawId = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const base64 = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/u, "");
const credentialId = base64(rawId);
let publicKey: `0x${string}`;
let spki: ArrayBuffer;
let change: (value: Record<string, any>) => void;
let request: CredentialCreationOptions | undefined;
let creates = 0;

beforeEach(async () => {
  creates = 0;
  change = () => {};
  request = undefined;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  publicKey = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  vi.stubGlobal("location", new URL(origin));
  vi.stubGlobal("navigator", {
    credentials: {
      create: async (options: CredentialCreationOptions) => {
        creates++;
        request = options;
        const data = new Uint8Array(55 + rawId.length + 1);
        data.set(hexToBytes(sha256(stringToBytes(rpId))));
        data[32] = 0x45; // UP, UV, attested credential data
        data[54] = rawId.length;
        data.set(rawId, 55);
        data[data.length - 1] = 0xa0; // UA owns CBOR parsing; this unit exercises its decoded methods.
        const result = {
          type: "public-key",
          id: credentialId,
          rawId: rawId.slice().buffer,
          response: {
            clientDataJSON: stringToBytes(
              JSON.stringify({
                type: "webauthn.create",
                origin,
                challenge: base64(new Uint8Array(options.publicKey!.challenge as ArrayBuffer)),
                crossOrigin: false,
              }),
            ).buffer,
            getAuthenticatorData: () => data.buffer,
            getPublicKey: () => spki,
            getPublicKeyAlgorithm: () => -7,
          },
        };
        change(result);
        return result;
      },
    },
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("WebAuthn enrolment", () => {
  it("binds a parent RP, requires UV, and preserves the existing raw-ID hash convention", async () => {
    const result = await enrolWebAuthnCredential({
      rpId,
      userName: "operator",
      excludeCredentialIds: [credentialId],
    });
    expect(result).toEqual({
      credentialId,
      publicKey,
      profile: {
        version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
        kind: "webauthn",
        publicKey,
        authenticatorIdHash: keccak256(rawId),
      },
    });
    expect(Object.isFrozen(result.profile)).toBe(true);
    expect(request?.publicKey).toMatchObject({
      rp: { id: rpId },
      authenticatorSelection: { userVerification: "required" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    });
    expect(new Uint8Array(request!.publicKey!.excludeCredentials![0]!.id as ArrayBuffer)).toEqual(
      rawId,
    );
    expect(
      kernelKey({
        kind: "webauthn",
        credential: result.profile,
        credentialId,
        rpId,
        origin,
        authenticate: async () => {
          throw new Error("not called");
        },
      }).kind,
    ).toBe("webauthn");
    expect(creates).toBe(1);
  });

  it.each([
    [
      "RP hash",
      "rp-mismatch",
      (v: any) => {
        const data = new Uint8Array(v.response.getAuthenticatorData());
        data[0] = data[0]! ^ 1;
      },
    ],
    [
      "UV",
      "user-verification",
      (v: any) => {
        new Uint8Array(v.response.getAuthenticatorData())[32] = 0x41;
      },
    ],
    [
      "UP",
      "user-verification",
      (v: any) => {
        new Uint8Array(v.response.getAuthenticatorData())[32] = 0x44;
      },
    ],
    [
      "credential ID",
      "invalid-attestation",
      (v: any) => {
        v.id = "AAAA";
      },
    ],
    [
      "embedded ID",
      "invalid-attestation",
      (v: any) => {
        const data = new Uint8Array(v.response.getAuthenticatorData());
        data[55] = data[55]! ^ 1;
      },
    ],
    [
      "algorithm",
      "invalid-attestation",
      (v: any) => {
        v.response.getPublicKeyAlgorithm = () => -257;
      },
    ],
    [
      "key",
      "invalid-attestation",
      (v: any) => {
        v.response.getPublicKey = () => new ArrayBuffer(3);
      },
    ],
    [
      "truncation",
      "invalid-attestation",
      (v: any) => {
        v.response.getAuthenticatorData = () => new ArrayBuffer(37);
      },
    ],
    [
      "challenge",
      "invalid-attestation",
      (v: any) => {
        v.response.clientDataJSON = stringToBytes(
          JSON.stringify({ type: "webauthn.create", origin, challenge: "wrong" }),
        ).buffer;
      },
    ],
    [
      "origin",
      "rp-mismatch",
      (v: any) => {
        const client = JSON.parse(new TextDecoder().decode(v.response.clientDataJSON));
        client.origin = "https://other.example.com";
        v.response.clientDataJSON = stringToBytes(JSON.stringify(client)).buffer;
      },
    ],
  ] as const)("rejects wrong %s without retry", async (_name, code, mutate) => {
    change = mutate;
    await expect(enrolWebAuthnCredential({ rpId, userName: "operator" })).rejects.toMatchObject({
      code,
    });
    expect(creates).toBe(1);
  });

  it.each([
    ["SecurityError", "rp-mismatch"],
    ["InvalidStateError", "already-registered"],
    ["AbortError", "cancelled"],
    ["NotAllowedError", "cancelled"],
    ["TimeoutError", "timeout"],
    ["ConstraintError", "user-verification"],
  ])("maps %s without exposing browser prose", async (name, code) => {
    const cause = new DOMException("untrusted-browser-prose", name);
    vi.stubGlobal("navigator", {
      credentials: {
        create: async () => {
          throw cause;
        },
      },
    });
    const error = await enrolWebAuthnCredential({ rpId, userName: "operator" }).catch(
      (error) => error,
    );
    expect(error).toMatchObject({ code });
    expect(error.cause).toBe(cause);
    expect(JSON.stringify(error)).not.toContain("untrusted-browser-prose");
    expect(Object.getOwnPropertyDescriptor(error, "cause")?.enumerable).toBe(false);
    expect(String(error)).not.toContain("untrusted-browser-prose");
  });

  it("rejects a wrong RP and a pre-aborted signal before opening the authenticator", async () => {
    await expect(
      enrolWebAuthnCredential({ rpId: "unrelated.com", userName: "operator" }),
    ).rejects.toMatchObject({ code: "rp-mismatch" });
    await expect(
      enrolWebAuthnCredential({ rpId, userName: "operator", signal: AbortSignal.abort() }),
    ).rejects.toMatchObject({ code: "cancelled" });
    expect(creates).toBe(0);
  });

  it("aborts a stalled ceremony at the SDK deadline", async () => {
    vi.useFakeTimers();
    let aborted = false;
    vi.stubGlobal("navigator", {
      credentials: {
        create: (options: CredentialCreationOptions) =>
          new Promise((_, reject) => {
            options.signal!.addEventListener(
              "abort",
              () => {
                aborted = true;
                reject(options.signal!.reason);
              },
              { once: true },
            );
          }),
      },
    });
    const result = enrolWebAuthnCredential({ rpId, userName: "operator" }).catch((error) => error);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(await result).toMatchObject({ code: "timeout" });
    expect(aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("cancels an active ceremony and removes its deadline", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    vi.stubGlobal("navigator", {
      credentials: {
        create: (options: CredentialCreationOptions) =>
          new Promise((_, reject) => {
            options.signal!.addEventListener("abort", () => reject(options.signal!.reason), {
              once: true,
            });
          }),
      },
    });
    const result = enrolWebAuthnCredential({
      rpId,
      userName: "operator",
      signal: controller.signal,
    }).catch((error) => error);
    controller.abort();
    expect(await result).toMatchObject({ code: "cancelled" });
    expect((await result).cause).toBe(controller.signal.reason);
    expect(vi.getTimerCount()).toBe(0);
  });
});
