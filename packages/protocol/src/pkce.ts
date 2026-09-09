/**
 * PKCE S256 challenge derivation shared by applications and relay consumers.
 * Authorization records and one-time consumption belong to @oaath/server.
 *
 * @author taek <leekt216@gmail.com>
 */
import { sha256, stringToBytes } from "viem";
import { protocolFailure } from "./errors.js";
import type { CaptureFailure } from "./internal/exact-record.js";

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const CODE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/u;

function base64UrlDigest(bytes: Uint8Array): string {
  let pending = 0;
  let bits = 0;
  let encoded = "";
  for (const byte of bytes) {
    pending = (pending << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      encoded += B64URL_ALPHABET.charAt((pending >> bits) & 63);
    }
  }
  return bits === 0 ? encoded : encoded + B64URL_ALPHABET.charAt((pending << (6 - bits)) & 63);
}

/** The only owner of the RFC 7636 S256 challenge derivation. */
export function deriveCodeChallenge(
  codeVerifier: unknown,
  fail: CaptureFailure = protocolFailure("authorization_code_verifier_mismatch"),
): string {
  if (typeof codeVerifier !== "string" || !CODE_VERIFIER.test(codeVerifier)) {
    return fail("PKCE code verifier must be 43 to 128 unreserved characters");
  }
  return base64UrlDigest(sha256(stringToBytes(codeVerifier), "bytes"));
}
