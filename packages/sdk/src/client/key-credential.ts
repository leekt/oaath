/**
 * The one boundary binding approved credential profiles to executable keys.
 *
 * A permission request cryptographically binds the owner and operator
 * credential profiles the owner reviews, but the runtime executes with the
 * KeyProfiles the composition injected. This module derives each key's
 * canonical credential identity from its actual public material — never from
 * an assertion beside it — and refuses the realm when it is not exactly the
 * approved profile. `@oaath/protocol` stays the sole owner of profile
 * equality; nothing here restates it.
 *
 * Derivation reads only public identity material. A kind with no approvable
 * credential shape (a consumer-authored `custom:` kind, or a key on an axis
 * its kind cannot serve, like a raw P-256 operator) derives nothing and is
 * refused: the normal application path may not inject a signer the owner
 * could never have reviewed.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
  type OperatorCredentialProfile,
  type OwnerCredentialProfile,
  parseOperatorCredentialProfile,
  parseOwnerCredentialProfile,
  sameOperatorCredentialProfile,
  sameOwnerCredentialProfile,
} from "@oaath/protocol";
import type { KeyProfile } from "../kernel/types.js";
import type { OaathBinding } from "./binding.js";
import { clientFail, mapClientFailure } from "./errors.js";

const ADDRESS_MATERIAL = /^0x[0-9a-f]{40}$/u;
/** abi.encode(uint256 x, uint256 y): the raw P-256 point without the 0x04 tag. */
const P256_MATERIAL = /^0x[0-9a-f]{128}$/u;
/** abi.encode(uint256 x, uint256 y, bytes32 authenticatorIdHash). */
const WEBAUTHN_MATERIAL = /^0x[0-9a-f]{192}$/u;

/**
 * The credential identity a key's public material actually is, or null when
 * the kind or material shape has no approvable owner credential form. Parsing
 * through the protocol owner keeps the derived profile canonical (including
 * the on-curve check) instead of trusting the material blindly.
 */
export function deriveOwnerCredentialProfile(
  key: Readonly<KeyProfile>,
): Readonly<OwnerCredentialProfile> | null {
  const material = key.publicMaterial;
  try {
    if (key.kind === "ecdsa" && ADDRESS_MATERIAL.test(material)) {
      return parseOwnerCredentialProfile({
        version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
        kind: "ecdsa",
        address: material,
      });
    }
    if (key.kind === "p256" && P256_MATERIAL.test(material)) {
      return parseOwnerCredentialProfile({
        version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
        kind: "p256",
        publicKey: `0x04${material.slice(2)}`,
      });
    }
    if (key.kind === "webauthn" && WEBAUTHN_MATERIAL.test(material)) {
      return parseOwnerCredentialProfile({
        version: OAATH_OWNER_CREDENTIAL_PROFILE_VERSION,
        kind: "webauthn",
        publicKey: `0x04${material.slice(2, 130)}`,
        authenticatorIdHash: `0x${material.slice(130)}`,
      });
    }
    return null;
  } catch {
    return null;
  }
}

/** The operator counterpart; the operator vocabulary carries no raw P-256 form. */
export function deriveOperatorCredentialProfile(
  key: Readonly<KeyProfile>,
): Readonly<OperatorCredentialProfile> | null {
  const material = key.publicMaterial;
  try {
    if (key.kind === "ecdsa" && ADDRESS_MATERIAL.test(material)) {
      return parseOperatorCredentialProfile({
        version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
        kind: "ecdsa",
        address: material,
      });
    }
    if (key.kind === "webauthn" && WEBAUTHN_MATERIAL.test(material)) {
      return parseOperatorCredentialProfile({
        version: OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
        kind: "webauthn",
        publicKey: `0x04${material.slice(2, 130)}`,
        authenticatorIdHash: `0x${material.slice(130)}`,
      });
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Refuses the realm unless each injected key is exactly the approved
 * credential. Runs at composition time, before any connection, quote,
 * preparation, signature, or submission can exist, so one approved profile
 * identifies one executable key for the realm's whole lifetime.
 */
export function requireApprovedKeyBinding(input: {
  readonly binding: Readonly<OaathBinding>;
  readonly ownerKey: Readonly<KeyProfile>;
  readonly sessionKey: Readonly<KeyProfile>;
}): void {
  try {
    const owner = deriveOwnerCredentialProfile(input.ownerKey);
    if (
      owner === null ||
      !sameOwnerCredentialProfile(owner, input.binding.account.ownerCredential)
    ) {
      clientFail(
        "oaath_client_capability_invalid",
        "the owner key is not the approved owner credential",
        "owner_credential_mismatch",
      );
    }
    const operator = deriveOperatorCredentialProfile(input.sessionKey);
    if (
      operator === null ||
      !sameOperatorCredentialProfile(operator, input.binding.operatorCredential)
    ) {
      clientFail(
        "oaath_client_capability_invalid",
        "the session key is not the approved operator credential",
        "operator_credential_mismatch",
      );
    }
  } catch (error) {
    mapClientFailure(error, "key credential binding could not be proven");
  }
}
