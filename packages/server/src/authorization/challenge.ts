/**
 * PKCE S256 challenge verification and the relay's random/digest primitives.
 *
 * Only WebCrypto and base64url are used, so this file stays platform-neutral.
 * The verifier is never stored: the store holds the S256 challenge, and consume
 * recomputes it.
 *
 * @author taek <leekt216@gmail.com>
 */

import { relayFailure } from "../relay/errors.js";

/** RFC 7636 code verifier: 43-128 unreserved characters. */
const CODE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/u;

const IDENTIFIER_BYTES = 32;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** 256 bits of CSPRNG output, base64url encoded. */
export function randomIdentifier(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(IDENTIFIER_BYTES)));
}

export async function sha256Base64Url(value: string): Promise<string> {
  let digest: ArrayBuffer;
  try {
    digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  } catch {
    return relayFailure("relay_internal", "WebCrypto SHA-256 is unavailable");
  }
  return base64Url(new Uint8Array(digest));
}

function timingSafeEqualText(left: string, right: string): boolean {
  // Both operands are base64url digests, so length is not itself a secret.
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

/**
 * True only when `codeVerifier` is a well-formed RFC 7636 verifier whose S256
 * digest equals the stored challenge. Any malformed input is a mismatch.
 */
export async function verifyPkceS256(
  codeVerifier: string,
  storedCodeChallenge: string,
): Promise<boolean> {
  if (!CODE_VERIFIER.test(codeVerifier)) return false;
  return timingSafeEqualText(await sha256Base64Url(codeVerifier), storedCodeChallenge);
}

/** True when the value can be a stored S256 challenge (43 base64url characters). */
export function isCodeChallengeS256(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/u.test(value);
}
