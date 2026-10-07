/** One immutable KMS-sealed key per authenticated identity. Registry durability
 * and KMS configuration are explicit deployment capabilities; recovery and signing
 * never create or rotate a key. No plaintext scalar is persisted or returned.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  type EcdsaOperatorCredentialProfile,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
} from "@oaath/protocol";
import type { RelayKms } from "../security/kms.js";
import {
  captureSignerBinding,
  captureSignerCredential,
  captureSignerIdentity,
  OAATH_SESSION_SIGNER_BINDING_VERSION,
  type SessionSignerBinding,
  SessionSignerError,
  type SessionSignerIdentity,
  type SessionSignerRegistry,
  signerIdentityKey,
  signerRecord,
  signerText,
} from "./registry.js";

export type { SessionSignerIdentity } from "./registry.js";
export interface SessionSignerRecoveryRequest extends SessionSignerIdentity {
  readonly expectedCredential: Readonly<EcdsaOperatorCredentialProfile>;
}
export interface SessionSignerSignRequest extends SessionSignerRecoveryRequest {
  /** One exact digest, never a message to interpret. */
  readonly hash: `0x${string}`;
}
export interface RelaySessionSignerProvider {
  /** Explicit first creation. Concurrent/repeated calls return the committed winner. */
  readonly createCredential: (request: Readonly<SessionSignerIdentity>) => Promise<unknown>;
  /** Read-only recovery of the exact previously approved credential. */
  readonly credential: (request: Readonly<SessionSignerRecoveryRequest>) => Promise<unknown>;
  readonly sign: (request: Readonly<SessionSignerSignRequest>) => Promise<unknown>;
}
function credentialOf(scalar: Uint8Array): Readonly<EcdsaOperatorCredentialProfile> {
  return Object.freeze({
    version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
    kind: "ecdsa",
    address: `0x${bytesToHex(keccak_256(secp256k1.getPublicKey(scalar, false).slice(1)).slice(12))}`,
  });
}
export function createKmsSessionSignerProvider(input: {
  readonly kms: RelayKms;
  readonly registry: SessionSignerRegistry;
  readonly providerId: string;
}) {
  const options = signerRecord(input, ["kms", "registry", "providerId"]);
  const providerId = signerText(options.providerId);
  const captureCapabilities = () => {
    try {
      const kms = options.kms as RelayKms;
      const registry = options.registry as SessionSignerRegistry;
      return Object.freeze({
        encrypt: kms.encrypt.bind(kms),
        decrypt: kms.decrypt.bind(kms),
        read: registry.read.bind(registry),
        create: registry.create.bind(registry),
      });
    } catch {
      throw new SessionSignerError("session_signer_input_invalid");
    }
  };
  const capabilities = captureCapabilities();
  async function open(binding: Readonly<SessionSignerBinding>): Promise<Uint8Array> {
    let scalar: Uint8Array | undefined;
    try {
      const plaintext = await capabilities.decrypt(binding.sealedReference);
      if (typeof plaintext !== "string" || !/^[0-9a-f]{64}$/u.test(plaintext)) throw new Error();
      scalar = hexToBytes(plaintext);
      if (credentialOf(scalar).address !== binding.credential.address) throw new Error();
      return scalar;
    } catch {
      scalar?.fill(0);
      throw new SessionSignerError("session_signer_custody_unavailable");
    }
  }
  function bindingFor(value: unknown, identity: Readonly<SessionSignerIdentity>) {
    if (value === null) throw new SessionSignerError("session_signer_binding_unavailable");
    const binding = captureSignerBinding(value);
    if (
      signerIdentityKey(binding.identity) !== signerIdentityKey(identity) ||
      binding.providerId !== providerId
    ) {
      throw new SessionSignerError("session_signer_binding_mismatch");
    }
    return binding;
  }
  async function recover(value: unknown, signing: boolean) {
    const record = signerRecord(value, [
      "clientId",
      "subject",
      "deviceId",
      "expectedCredential",
      ...(signing ? ["hash"] : []),
    ]);
    const identity = captureSignerIdentity({
      clientId: record.clientId,
      subject: record.subject,
      deviceId: record.deviceId,
    });
    const expected = captureSignerCredential(record.expectedCredential);
    if (signing && (typeof record.hash !== "string" || !/^0x[0-9a-f]{64}$/u.test(record.hash))) {
      throw new SessionSignerError("session_signer_input_invalid");
    }
    let raw: unknown;
    try {
      raw = await capabilities.read(signerIdentityKey(identity));
    } catch {
      throw new SessionSignerError("session_signer_registry_unavailable");
    }
    const binding = bindingFor(raw, identity);
    if (binding.credential.address !== expected.address)
      throw new SessionSignerError("session_signer_binding_mismatch");
    return { binding, hash: record.hash as `0x${string}` };
  }
  return Object.freeze({
    async createCredential(
      request: Readonly<SessionSignerIdentity>,
    ): Promise<Readonly<EcdsaOperatorCredentialProfile>> {
      const identity = captureSignerIdentity(request);
      let raw: unknown;
      try {
        raw = await capabilities.create(signerIdentityKey(identity), async () => {
          const scalar = secp256k1.utils.randomPrivateKey();
          try {
            const credential = credentialOf(scalar);
            const sealedReference = signerText(
              await capabilities.encrypt(bytesToHex(scalar)),
              65_536,
            );
            const binding = Object.freeze({
              version: OAATH_SESSION_SIGNER_BINDING_VERSION,
              identity,
              providerId,
              credential,
              sealedReference,
            });
            const verified = await open(binding);
            verified.fill(0);
            return binding;
          } catch {
            throw new SessionSignerError("session_signer_custody_unavailable");
          } finally {
            scalar.fill(0);
          }
        });
      } catch (error) {
        if (error instanceof SessionSignerError) throw error;
        throw new SessionSignerError("session_signer_registry_unavailable");
      }
      const binding = bindingFor(raw, identity);
      const scalar = await open(binding);
      scalar.fill(0);
      return binding.credential;
    },
    async credential(request: Readonly<SessionSignerRecoveryRequest>) {
      const { binding } = await recover(request, false);
      const scalar = await open(binding);
      scalar.fill(0);
      return binding.credential;
    },
    async sign(request: Readonly<SessionSignerSignRequest>): Promise<`0x${string}`> {
      const { binding, hash } = await recover(request, true);
      const scalar = await open(binding);
      try {
        const signature = secp256k1.sign(hexToBytes(hash.slice(2)), scalar, { lowS: true });
        if (signature.recovery !== 0 && signature.recovery !== 1)
          throw new SessionSignerError("session_signer_custody_unavailable");
        return `0x${bytesToHex(signature.toCompactRawBytes())}${(27 + signature.recovery).toString(16)}`;
      } finally {
        scalar.fill(0);
      }
    },
  }) satisfies RelaySessionSignerProvider;
}
