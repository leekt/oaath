/**
 * A KeyProfile from an approved public credential alone, with no signer.
 *
 * In the service-bootstrapped browser path the application never holds an
 * owner signer: root signing happens on the owner device and arrives through
 * the authorization protocol. The realm still needs the owner's *identity* —
 * to derive and bind the Kernel account and to prove the #77 credential
 * binding — so this profile carries exactly the public material the approved
 * credential states and refuses to sign anything.
 * The owner service also uses it to derive permission packages from an
 * operator's reviewed public credential, without owning the application key.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type CaptureContext,
  captureRecord,
  OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION,
  type OperatorCredentialProfile,
  type OwnerCredentialProfile,
  parseOperatorCredentialProfile,
  parseOwnerCredentialProfile,
} from "@oaath/protocol";
import { encodeAbiParameters } from "viem";
import type { KernelDeployment } from "../deployment/profile.js";
import { exactInput, inputAddress, inputInvalid, runtimeFail } from "../internal.js";
import { exactKernelDeployment, resolvePinnedValidator } from "../modules.js";
import type { KeyProfile } from "../types.js";
import { webauthnDummySignature } from "./webauthn.js";

const POINT_PARAMETERS = [
  { name: "x", type: "uint256" },
  { name: "y", type: "uint256" },
] as const;
const WEBAUTHN_MATERIAL_PARAMETERS = [
  { name: "x", type: "uint256" },
  { name: "y", type: "uint256" },
  { name: "authenticatorIdHash", type: "bytes32" },
] as const;

/** Fixed-width placeholders for gas estimation; this profile never signs. */
const DUMMY: Readonly<Record<OwnerCredentialProfile["kind"], `0x${string}`>> = Object.freeze({
  ecdsa: `0x${"11".repeat(32)}${"22".repeat(32)}1c`,
  p256: `0x${"33".repeat(32)}${"44".repeat(32)}`,
  webauthn: webauthnDummySignature("https://example.invalid"),
});

const publicOnlySigners = new WeakSet<KeyProfile["sign"]>();

/** Internal availability fact; a public credential never offers a signing capability. */
export function credentialKeyIsReadOnly(key: Readonly<KeyProfile>): boolean {
  return publicOnlySigners.has(key.sign);
}

export interface CredentialKeyInput {
  /** Exact public protocol credential; owner/session behavior belongs to the operator. */
  readonly credential: Readonly<OwnerCredentialProfile | OperatorCredentialProfile>;
  /**
   * ECDSA root validator, if root authority will be composed. Session-only
   * public profiles need no root validator; other key kinds must carry null.
   */
  readonly validator: `0x${string}` | null;
}

/**
 * The public material each credential kind installs, byte-identical to what
 * the corresponding signing profile publishes, so the derived account is the
 * account the owner's own device derives.
 */
function publicMaterial(
  credential: Readonly<OwnerCredentialProfile | OperatorCredentialProfile>,
): `0x${string}` {
  if (credential.kind === "ecdsa") return credential.address;
  if (credential.kind === "p256") {
    return encodeAbiParameters(POINT_PARAMETERS, [
      BigInt(`0x${credential.publicKey.slice(4, 68)}`),
      BigInt(`0x${credential.publicKey.slice(68)}`),
    ]);
  }
  return encodeAbiParameters(WEBAUTHN_MATERIAL_PARAMETERS, [
    BigInt(`0x${credential.publicKey.slice(4, 68)}`),
    BigInt(`0x${credential.publicKey.slice(68)}`),
    credential.authenticatorIdHash,
  ]);
}

export function credentialKey(value: CredentialKeyInput): Readonly<KeyProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["credential", "validator"], "credential key", context);
  const captured = captureRecord(record.credential, "public credential", context, inputInvalid);
  let credential: Readonly<OwnerCredentialProfile | OperatorCredentialProfile>;
  try {
    credential =
      captured.version === OAATH_OPERATOR_CREDENTIAL_PROFILE_VERSION
        ? parseOperatorCredentialProfile(captured)
        : parseOwnerCredentialProfile(captured);
  } catch {
    return inputInvalid("credential key requires a valid public credential profile");
  }
  if (credential.kind !== "ecdsa" && record.validator !== null) {
    return inputInvalid("credential key validator does not match the credential kind");
  }
  const validator =
    record.validator === null ? null : inputAddress(record.validator, "credential owner validator");

  const profile: Readonly<KeyProfile> = Object.freeze({
    kind: credential.kind,
    publicMaterial: publicMaterial(credential),
    resolveValidator: (deployment: Readonly<KernelDeployment>) => {
      exactKernelDeployment(deployment);
      if (validator !== null) return validator;
      if (credential.kind === "ecdsa")
        return inputInvalid("ECDSA root authority requires a validator");
      return resolvePinnedValidator(credential.kind);
    },
    signerModule: null,
    dummySignature: DUMMY[credential.kind],
    async sign(): Promise<`0x${string}`> {
      return runtimeFail(
        "kernel_runtime_signing_failed",
        "a public credential profile cannot sign",
      );
    },
    async verify(): Promise<boolean> {
      return false;
    },
  });
  publicOnlySigners.add(profile.sign);
  return profile;
}
