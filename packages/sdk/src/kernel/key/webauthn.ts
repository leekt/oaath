/**
 * WebAuthn/passkey KeyProfile. Binds one credential to one relying party and
 * origin, requests assertions through a caller-owned authenticator capability,
 * verifies the returned assertion locally, and encodes the Kernel-native
 * signature envelope.
 *
 * @author taek <leekt216@gmail.com>
 */
import { p256 } from "@noble/curves/nist.js";
import { type CaptureContext, parseOwnerCredentialProfile } from "@oaath/protocol";
import {
  concat,
  decodeAbiParameters,
  encodeAbiParameters,
  hexToBytes,
  keccak256,
  sha256,
  stringToBytes,
  toHex,
} from "viem";
import type { KernelV4Deployment } from "../../kernel-v4.js";
import {
  exactInput,
  inputCapability,
  inputInvalid,
  inputUint,
  invokeCapability,
  isBytes,
  isHash,
  runtimeFail,
} from "../internal.js";
import { exactKernelDeployment, resolvePinnedValidator } from "../modules.js";
import type { KeyProfile } from "../types.js";

const BASE64URL = /^[A-Za-z0-9_-]{1,1024}$/u;
const RP_ID = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/u;
const ORIGIN = /^https:\/\/[a-z0-9.-]{1,253}(?::[0-9]{1,5})?$/u;
const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P256_HALF_ORDER = P256_ORDER / 2n;
const MAX_AUTHENTICATOR_DATA_BYTES = 2048;
const MAX_CLIENT_DATA_LENGTH = 4096;
const MIN_AUTHENTICATOR_DATA_BYTES = 37;
const TYPE_FIELD = '"type":"webauthn.get"';

/**
 * Signature envelope of the reviewed Kernel WebAuthn validator: the assertion
 * fields the module needs to recompute the signed message on-chain.
 */
const ASSERTION_PARAMETERS = [
  { name: "authenticatorData", type: "bytes" },
  { name: "clientDataJSON", type: "string" },
  { name: "responseTypeLocation", type: "uint256" },
  { name: "r", type: "uint256" },
  { name: "s", type: "uint256" },
  { name: "usePrecompiled", type: "bool" },
] as const;

const PUBLIC_MATERIAL_PARAMETERS = [
  { name: "x", type: "uint256" },
  { name: "y", type: "uint256" },
  { name: "authenticatorIdHash", type: "bytes32" },
] as const;

export interface WebAuthnAssertionRequest {
  /** The 32-byte hash to be signed; also the raw WebAuthn challenge. */
  readonly hash: `0x${string}`;
  /** base64url encoding of the challenge bytes, as it must appear in clientDataJSON. */
  readonly challenge: string;
  readonly rpId: string;
  readonly origin: string;
  readonly credentialId: string;
}

export interface WebAuthnKeyInput {
  /** @oaath/protocol WebAuthn credential profile carrying the public key and authenticator hash. */
  readonly credential: unknown;
  /** base64url credential ID whose keccak256 must equal the profile authenticatorIdHash. */
  readonly credentialId: string;
  readonly rpId: string;
  /** Exact expected clientDataJSON origin, for example https://app.example. */
  readonly origin: string;
  /** Caller-owned authenticator capability returning one WebAuthn assertion. */
  readonly authenticate: (request: WebAuthnAssertionRequest) => Promise<unknown>;
}

function base64UrlFromBytes(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
}

function bytesFromBase64Url(value: string): Uint8Array | undefined {
  try {
    const padded = value
      .replace(/-/gu, "+")
      .replace(/_/gu, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch {
    return undefined;
  }
}

function matchesAt(source: Uint8Array, expected: Uint8Array, offset: number): boolean {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset + expected.length > source.length) {
    return false;
  }
  return expected.every((byte, index) => source[offset + index] === byte);
}

export function webauthnKey(value: WebAuthnKeyInput): Readonly<KeyProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(
    value,
    ["credential", "credentialId", "rpId", "origin", "authenticate"],
    "WebAuthn key",
    context,
  );
  const credential = parseOwnerCredentialProfile(record.credential);
  if (credential.kind !== "webauthn") {
    return inputInvalid("WebAuthn key credential profile is not a WebAuthn credential");
  }
  if (typeof record.credentialId !== "string" || !BASE64URL.test(record.credentialId)) {
    return inputInvalid("WebAuthn key credential ID is invalid");
  }
  const credentialBytes = bytesFromBase64Url(record.credentialId);
  if (
    !credentialBytes ||
    credentialBytes.length === 0 ||
    base64UrlFromBytes(credentialBytes) !== record.credentialId
  ) {
    return inputInvalid("WebAuthn key credential ID is not canonical base64url");
  }
  if (keccak256(toHex(credentialBytes)) !== credential.authenticatorIdHash) {
    return inputInvalid("WebAuthn key credential ID does not match the credential profile");
  }
  if (
    typeof record.rpId !== "string" ||
    !RP_ID.test(record.rpId) ||
    record.rpId.includes("..") ||
    typeof record.origin !== "string" ||
    !ORIGIN.test(record.origin)
  ) {
    return inputInvalid("WebAuthn key relying-party binding is invalid");
  }
  const rpId = record.rpId;
  const origin = record.origin;
  const credentialId = record.credentialId;
  const rpIdHash = sha256(stringToBytes(rpId));
  const publicKey = credential.publicKey;
  const authenticate = inputCapability<WebAuthnKeyInput["authenticate"]>(
    record.authenticate,
    "WebAuthn key authenticator capability",
  );

  function verifyAssertion(
    hash: `0x${string}`,
    authenticatorData: `0x${string}`,
    clientDataJSON: string,
    responseTypeLocation: bigint,
    r: bigint,
    s: bigint,
  ): boolean {
    if (
      !isBytes(authenticatorData) ||
      (authenticatorData.length - 2) / 2 < MIN_AUTHENTICATOR_DATA_BYTES ||
      (authenticatorData.length - 2) / 2 > MAX_AUTHENTICATOR_DATA_BYTES ||
      clientDataJSON.length === 0 ||
      clientDataJSON.length > MAX_CLIENT_DATA_LENGTH ||
      responseTypeLocation > BigInt(Number.MAX_SAFE_INTEGER) ||
      r <= 0n ||
      r >= P256_ORDER ||
      s <= 0n ||
      s > P256_HALF_ORDER
    ) {
      return false;
    }
    if (authenticatorData.slice(0, 66) !== rpIdHash) return false;
    const flags = Number.parseInt(authenticatorData.slice(66, 68), 16);
    if (
      (flags & 0x01) === 0 ||
      (flags & 0x04) === 0 ||
      ((flags & 0x08) === 0 && (flags & 0x10) !== 0)
    ) {
      return false;
    }
    const clientData = stringToBytes(clientDataJSON);
    if (!matchesAt(clientData, stringToBytes(TYPE_FIELD), Number(responseTypeLocation))) {
      return false;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(clientDataJSON);
    } catch {
      return false;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const client = parsed as Record<string, unknown>;
    if (
      client.type !== "webauthn.get" ||
      client.challenge !== base64UrlFromBytes(hexToBytes(hash)) ||
      client.origin !== origin ||
      client.crossOrigin === true
    ) {
      return false;
    }
    const message = sha256(concat([authenticatorData, sha256(clientData)]));
    const compact = `0x${r.toString(16).padStart(64, "0")}${s
      .toString(16)
      .padStart(64, "0")}` as const;
    try {
      return p256.verify(hexToBytes(compact), hexToBytes(message), hexToBytes(publicKey), {
        format: "compact",
        lowS: true,
        prehash: false,
      });
    } catch {
      return false;
    }
  }

  async function verify(hash: `0x${string}`, signature: `0x${string}`): Promise<boolean> {
    if (!isBytes(signature) || !isHash(hash)) return false;
    let decoded: readonly [`0x${string}`, string, bigint, bigint, bigint, boolean];
    try {
      decoded = decodeAbiParameters(ASSERTION_PARAMETERS, signature);
    } catch {
      return false;
    }
    const [authenticatorData, clientDataJSON, responseTypeLocation, r, s, usePrecompiled] = decoded;
    if (usePrecompiled) return false;
    return verifyAssertion(
      hash,
      authenticatorData.toLowerCase() as `0x${string}`,
      clientDataJSON,
      responseTypeLocation,
      r,
      s,
    );
  }

  return Object.freeze({
    kind: "webauthn" as const,
    publicMaterial: encodeAbiParameters(PUBLIC_MATERIAL_PARAMETERS, [
      BigInt(`0x${publicKey.slice(4, 68)}`),
      BigInt(`0x${publicKey.slice(68)}`),
      credential.authenticatorIdHash,
    ]),
    resolveValidator: (deployment: Readonly<KernelV4Deployment>) => {
      exactKernelDeployment(deployment);
      return resolvePinnedValidator("webauthn");
    },
    dummySignature: encodeAbiParameters(ASSERTION_PARAMETERS, [
      `0x${"55".repeat(MIN_AUTHENTICATOR_DATA_BYTES)}`,
      `{"type":"webauthn.get","challenge":"${"A".repeat(43)}","origin":"${origin}"}`,
      1n,
      BigInt(`0x${"66".repeat(32)}`) % P256_ORDER,
      BigInt(`0x${"77".repeat(32)}`) % P256_HALF_ORDER,
      false,
    ]),
    async sign(hash: `0x${string}`): Promise<`0x${string}`> {
      if (!isHash(hash)) {
        return runtimeFail("kernel_runtime_signature_invalid", "WebAuthn challenge is invalid");
      }
      const produced = await invokeCapability(
        authenticate,
        Object.freeze({
          hash,
          challenge: base64UrlFromBytes(hexToBytes(hash)),
          rpId,
          origin,
          credentialId,
        }),
        "WebAuthn assertion request failed",
      );
      const assertion = exactInput(
        produced,
        ["authenticatorData", "clientDataJSON", "responseTypeLocation", "r", "s"],
        "WebAuthn assertion",
        new WeakSet(),
      );
      if (
        typeof assertion.authenticatorData !== "string" ||
        !isBytes(assertion.authenticatorData.toLowerCase()) ||
        typeof assertion.clientDataJSON !== "string" ||
        !isHash(assertion.r) ||
        !isHash(assertion.s)
      ) {
        return runtimeFail("kernel_runtime_signature_invalid", "WebAuthn assertion is invalid");
      }
      const rawS = BigInt(assertion.s);
      if (rawS <= 0n || rawS >= P256_ORDER) {
        return runtimeFail("kernel_runtime_signature_invalid", "WebAuthn assertion is invalid");
      }
      const signature = encodeAbiParameters(ASSERTION_PARAMETERS, [
        assertion.authenticatorData.toLowerCase() as `0x${string}`,
        assertion.clientDataJSON,
        inputUint(
          assertion.responseTypeLocation,
          BigInt(Number.MAX_SAFE_INTEGER),
          "WebAuthn assertion response type location",
        ),
        BigInt(assertion.r),
        rawS > P256_HALF_ORDER ? P256_ORDER - rawS : rawS,
        false,
      ]);
      if (!(await verify(hash, signature))) {
        return runtimeFail(
          "kernel_runtime_signature_invalid",
          "WebAuthn assertion does not match the bound credential",
        );
      }
      return signature;
    },
    verify,
  });
}
