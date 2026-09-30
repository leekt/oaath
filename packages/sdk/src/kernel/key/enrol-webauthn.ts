/** Browser-owned passkey creation; no attestation trust-chain claim or persisted state. */
import {
  captureDenseArray,
  captureRecord,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  parseOperatorCredentialProfile,
  type WebAuthnOperatorCredentialProfile,
} from "@oaath/protocol";
import { keccak256, sha256, stringToBytes, toHex } from "viem";
import { base64UrlFromBytes, bytesFromBase64Url } from "./webauthn.js";

export type WebAuthnEnrolmentErrorCode =
  | "input-invalid"
  | "unsupported"
  | "rp-mismatch"
  /** Includes browser denial; NotAllowedError intentionally hides more precise reasons. */
  | "cancelled"
  | "timeout"
  | "user-verification"
  | "already-registered"
  | "invalid-attestation";

/** Closed code/message; the original browser error is a non-enumerable cause, never for logging. */
export class OaathWebAuthnEnrolmentError extends Error {
  readonly code: WebAuthnEnrolmentErrorCode;
  constructor(code: WebAuthnEnrolmentErrorCode, options?: ErrorOptions) {
    super(`WebAuthn enrolment failed: ${code}`, options);
    this.code = code;
    this.name = "OaathWebAuthnEnrolmentError";
  }
}

export interface EnrolWebAuthnCredentialInput {
  /** Explicit RP domain: the current host or a browser-permitted parent domain. */
  readonly rpId: string;
  readonly userName: string;
  /** Canonical base64url credential IDs, as returned by an earlier enrolment. */
  readonly excludeCredentialIds?: readonly string[];
  readonly signal?: AbortSignal;
}

export interface EnrolledWebAuthnCredential {
  readonly profile: Readonly<WebAuthnOperatorCredentialProfile>;
  /** Canonical base64url of rawId; the profile hashes the raw bytes, not this text. */
  readonly credentialId: string;
  /** Uncompressed 65-byte SEC1 P-256 public key, including the 0x04 prefix. */
  readonly publicKey: `0x${string}`;
}

function fail(code: WebAuthnEnrolmentErrorCode, options?: ErrorOptions): never {
  throw new OaathWebAuthnEnrolmentError(code, options);
}

function errorCode(error: unknown): WebAuthnEnrolmentErrorCode {
  if (error instanceof OaathWebAuthnEnrolmentError) return error.code;
  const name = error instanceof DOMException ? error.name : undefined;
  switch (name) {
    case "SecurityError":
      return "rp-mismatch";
    case "InvalidStateError":
      return "already-registered";
    case "TimeoutError":
      return "timeout";
    case "AbortError":
    case "NotAllowedError":
      return "cancelled";
    case "ConstraintError":
      return "user-verification";
    case "NotSupportedError":
      return "unsupported";
    default:
      return "invalid-attestation";
  }
}

function credentialBytes(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,1024}$/u.test(value))
    return fail("input-invalid");
  const bytes = bytesFromBase64Url(value);
  if (!bytes || bytes.length === 0 || base64UrlFromBytes(bytes) !== value)
    return fail("input-invalid");
  return new Uint8Array(bytes);
}

/**
 * Creates one ES256 passkey with required user verification and a 60-second
 * deadline. Uses the native Level 2 getPublicKey/getAuthenticatorData methods
 * (https://www.w3.org/TR/webauthn-3/#sctn-public-key-easy) for CBOR/COSE extraction.
 * Save the returned public result before using it with kernelKey. Never retries;
 * a failure after authenticator creation cannot delete the authenticator's key.
 */
export async function enrolWebAuthnCredential(
  value: EnrolWebAuthnCredentialInput,
): Promise<Readonly<EnrolledWebAuthnCredential>> {
  const context = new WeakSet();
  const invalid = () => fail("input-invalid");
  const input = captureRecord(value, "WebAuthn enrolment", context, invalid);
  if (
    Object.keys(input).some(
      (key) => !["rpId", "userName", "excludeCredentialIds", "signal"].includes(key),
    )
  )
    invalid();
  if (
    typeof input.rpId !== "string" ||
    !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/u.test(input.rpId) ||
    input.rpId.includes("..") ||
    typeof input.userName !== "string" ||
    input.userName.trim().length === 0 ||
    input.userName.length > 256
  )
    return invalid();
  const { rpId, userName } = input;
  if (
    typeof navigator === "undefined" ||
    typeof navigator.credentials?.create !== "function" ||
    typeof location === "undefined" ||
    !globalThis.crypto?.subtle
  )
    return fail("unsupported");
  const origin = location.origin;
  const host = location.hostname;
  if (
    (host !== rpId && !host.endsWith(`.${rpId}`)) ||
    (location.protocol !== "https:" &&
      !(location.protocol === "http:" && (host === "localhost" || host.endsWith(".localhost"))))
  )
    return fail("rp-mismatch");
  const excluded =
    input.excludeCredentialIds === undefined
      ? []
      : captureDenseArray(input.excludeCredentialIds, "excluded credentials", context, invalid);
  if (excluded.length > 64) return invalid();
  const excludeCredentials = excluded.map((id) => ({
    type: "public-key" as const,
    id: credentialBytes(id),
  }));
  const externalSignal = input.signal;
  if (externalSignal !== undefined && !(externalSignal instanceof AbortSignal)) return invalid();
  if (externalSignal?.aborted)
    return fail(errorCode(externalSignal.reason) === "timeout" ? "timeout" : "cancelled", {
      cause: externalSignal.reason,
    });
  const controller = new AbortController();
  const abort = () => controller.abort(externalSignal?.reason);
  externalSignal?.addEventListener("abort", abort, { once: true });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new DOMException("WebAuthn deadline", "TimeoutError"));
  }, 60_000);
  try {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const credential = (await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: rpId },
        user: {
          id: crypto.getRandomValues(new Uint8Array(32)),
          name: userName,
          displayName: userName,
        },
        challenge,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
        attestation: "none",
        timeout: 60_000,
        excludeCredentials,
      },
      signal: controller.signal,
    })) as PublicKeyCredential | null;
    if (controller.signal.aborted)
      return fail(timedOut ? "timeout" : "cancelled", { cause: controller.signal.reason });
    if (!credential || credential.type !== "public-key") return fail("invalid-attestation");
    const rawId = new Uint8Array(credential.rawId);
    const credentialId = base64UrlFromBytes(rawId);
    if (credential.id !== credentialId || rawId.length < 1 || credentialId.length > 1024)
      return fail("invalid-attestation");
    const response = credential.response as AuthenticatorAttestationResponse;
    if (
      typeof response.getAuthenticatorData !== "function" ||
      typeof response.getPublicKey !== "function" ||
      typeof response.getPublicKeyAlgorithm !== "function"
    )
      return fail("unsupported");
    const data = new Uint8Array(response.getAuthenticatorData());
    if (data.length < 55 || data.length > 65536 || (data[32]! & 0x40) === 0)
      return fail("invalid-attestation");
    if (toHex(data.slice(0, 32)) !== sha256(stringToBytes(rpId))) return fail("rp-mismatch");
    const flags = data[32]!;
    if ((flags & 0x05) !== 0x05) return fail("user-verification");
    if ((flags & 0x08) === 0 && (flags & 0x10) !== 0) return fail("invalid-attestation");
    const idLength = (data[53]! << 8) | data[54]!;
    if (
      idLength !== rawId.length ||
      55 + idLength >= data.length ||
      toHex(data.slice(55, 55 + idLength)) !== toHex(rawId)
    )
      return fail("invalid-attestation");
    if (response.clientDataJSON.byteLength > 4096) return fail("invalid-attestation");
    const client = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(response.clientDataJSON),
    );
    if (client.origin !== origin || client.crossOrigin === true) return fail("rp-mismatch");
    if (client.type !== "webauthn.create" || client.challenge !== base64UrlFromBytes(challenge))
      return fail("invalid-attestation");
    const spki = response.getPublicKey();
    if (response.getPublicKeyAlgorithm() !== -7 || !spki || spki.byteLength > 1024)
      return fail("invalid-attestation");
    const key = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    const publicKey = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
    const profile = parseOperatorCredentialProfile({
      version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn",
      publicKey,
      authenticatorIdHash: keccak256(rawId),
    }) as Readonly<WebAuthnOperatorCredentialProfile>;
    if (controller.signal.aborted)
      return fail(timedOut ? "timeout" : "cancelled", { cause: controller.signal.reason });
    return Object.freeze({ profile, credentialId, publicKey });
  } catch (error) {
    if (error instanceof OaathWebAuthnEnrolmentError && !timedOut && !externalSignal?.aborted)
      throw error;
    return fail(
      timedOut
        ? "timeout"
        : externalSignal?.aborted
          ? errorCode(externalSignal.reason) === "timeout"
            ? "timeout"
            : "cancelled"
          : errorCode(error),
      { cause: error instanceof OaathWebAuthnEnrolmentError ? error.cause : error },
    );
  } finally {
    clearTimeout(timer);
    externalSignal?.removeEventListener("abort", abort);
  }
}
