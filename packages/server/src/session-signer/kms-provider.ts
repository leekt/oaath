/**
 * Reference hosted session-signer provider: one KMS-sealed secp256k1 operator
 * key per authenticated `(clientId, subject, deviceId)` identity, signing one
 * exact 32-byte hash at a time.
 *
 * Custody boundary: the private scalar exists in plaintext only inside this
 * process during key generation and signing; at rest it is exactly one
 * KMS-sealed string. No route, log, or return value ever carries key material
 * — `credential` answers the public operator profile and `sign` answers one
 * 65-byte ECDSA signature.
 *
 * Rotation invariant: one identity maps to one credential for this provider's
 * lifetime. There is no rotation path here — a new key requires a new
 * identity, and therefore a newly approved Grant; nothing can silently swap
 * the public key under an existing approval.
 *
 * Like `createMemoryRelayStore`, the in-memory registry makes this a
 * reference implementation, not a production durability claim: a deployment
 * that must survive restarts persists the sealed entries in its own store.
 *
 * @author taek <leekt216@gmail.com>
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION } from "@oaath/protocol";
import type { RelayKms } from "../security/kms.js";

const HASH = /^0x[0-9a-f]{64}$/u;
const MAX_IDENTITY_PART = 256;

export interface SessionSignerIdentity {
  readonly clientId: string;
  readonly subject: string;
  readonly deviceId: string;
}

export interface SessionSignerSignRequest extends SessionSignerIdentity {
  /** The exact 32-byte hash to sign; never a message to interpret. */
  readonly hash: `0x${string}`;
}

export interface RelaySessionSignerProvider {
  /**
   * The operator credential for one authenticated identity, creating the key
   * on first use. Idempotent: the same identity always answers the same
   * credential.
   */
  readonly credential: (request: Readonly<SessionSignerIdentity>) => Promise<unknown>;
  /** One ECDSA signature over one exact hash, under that identity's key. */
  readonly sign: (request: Readonly<SessionSignerSignRequest>) => Promise<unknown>;
}

function identityKey(request: Readonly<SessionSignerIdentity>): string {
  for (const part of [request.clientId, request.subject, request.deviceId]) {
    if (typeof part !== "string" || part.length < 1 || part.length > MAX_IDENTITY_PART) {
      throw new Error("session signer identity is invalid");
    }
  }
  // JSON array form: no separator inside a part can collide two identities.
  return JSON.stringify([request.clientId, request.subject, request.deviceId]);
}

function addressOf(privateKey: Uint8Array): `0x${string}` {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return `0x${bytesToHex(keccak_256(publicKey.slice(1)).slice(12))}`;
}

export function createKmsSessionSignerProvider(input: {
  readonly kms: RelayKms;
}): RelaySessionSignerProvider {
  const kms = input.kms;
  /** identity -> KMS-sealed private scalar; the only at-rest key form. */
  const sealed = new Map<string, string>();
  /** Serializes first-use creation so one identity never mints two keys. */
  const creating = new Map<string, Promise<string>>();

  async function sealedKeyFor(identity: string): Promise<string> {
    const existing = sealed.get(identity);
    if (existing !== undefined) return existing;
    const pending =
      creating.get(identity) ??
      (async () => {
        const scalar = secp256k1.utils.randomPrivateKey();
        const reference = String(await kms.encrypt(bytesToHex(scalar)));
        scalar.fill(0);
        sealed.set(identity, reference);
        return reference;
      })();
    creating.set(identity, pending);
    pending.finally(() => creating.delete(identity));
    return pending;
  }

  return Object.freeze({
    async credential(request: Readonly<SessionSignerIdentity>): Promise<unknown> {
      const identity = identityKey(request);
      const privateKey = hexToBytes(String(await kms.decrypt(await sealedKeyFor(identity))));
      try {
        return Object.freeze({
          version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
          kind: "ecdsa" as const,
          address: addressOf(privateKey),
        });
      } finally {
        privateKey.fill(0);
      }
    },
    async sign(request: Readonly<SessionSignerSignRequest>): Promise<unknown> {
      const identity = identityKey(request);
      if (typeof request.hash !== "string" || !HASH.test(request.hash)) {
        throw new Error("session signer hash must be one exact 32-byte hash");
      }
      // Signing never creates a key: an identity that never fetched its
      // credential holds no approval that could authorize a signature.
      const reference = sealed.get(identity);
      if (reference === undefined) {
        throw new Error("session signer identity holds no credential");
      }
      const privateKey = hexToBytes(String(await kms.decrypt(reference)));
      try {
        const signature = secp256k1.sign(hexToBytes(request.hash.slice(2)), privateKey, {
          lowS: true,
        });
        if (signature.recovery !== 0 && signature.recovery !== 1) {
          throw new Error("session signer produced an unusable signature");
        }
        // 65-byte r ‖ s ‖ v with v in {27, 28}: the exact shape a locally held
        // viem account produces, so the Kernel-side validation is identical.
        return `0x${bytesToHex(signature.toCompactRawBytes())}${(27 + signature.recovery).toString(16)}`;
      } finally {
        privateKey.fill(0);
      }
    },
  });
}
