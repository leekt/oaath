/**
 * Owner KeyProfile from an approved credential profile alone.
 *
 * In the service-bootstrapped browser path the application never holds an
 * owner signer: root signing happens on the owner device and arrives through
 * the authorization protocol. The realm still needs the owner's *identity* —
 * to derive and bind the Kernel account and to prove the #77 credential
 * binding — so this profile carries exactly the public material the approved
 * credential states and refuses to sign anything.
 *
 * @author taek <leekt216@gmail.com>
 */
import type { CaptureContext, OwnerCredentialProfile } from "@oaath/protocol";
import { encodeAbiParameters } from "viem";
import type { KernelV4Deployment } from "../../kernel-v4.js";
import { exactInput, inputAddress, inputInvalid, runtimeFail } from "../internal.js";
import { exactKernelDeployment, resolvePinnedValidator } from "../modules.js";
import type { KeyProfile } from "../types.js";

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
  webauthn: `0x${"55".repeat(64)}`,
});

export interface CredentialOwnerKeyInput {
  /** Parsed `@oaath/protocol` owner credential profile. */
  readonly credential: Readonly<OwnerCredentialProfile>;
  /**
   * Caller-bound ECDSA validator module, required exactly when the credential
   * is ecdsa (Kernel v4 pins no ECDSA validator); other kinds must carry null.
   */
  readonly validator: `0x${string}` | null;
}

/**
 * The public material each credential kind installs, byte-identical to what
 * the corresponding signing profile publishes, so the derived account is the
 * account the owner's own device derives.
 */
function publicMaterial(credential: Readonly<OwnerCredentialProfile>): `0x${string}` {
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

export function credentialOwnerKey(value: CredentialOwnerKeyInput): Readonly<KeyProfile> {
  const context: CaptureContext = new WeakSet();
  const record = exactInput(value, ["credential", "validator"], "credential owner key", context);
  const credential = record.credential as Readonly<OwnerCredentialProfile>;
  if (
    credential === null ||
    typeof credential !== "object" ||
    (credential.kind !== "ecdsa" && credential.kind !== "p256" && credential.kind !== "webauthn")
  ) {
    return inputInvalid("credential owner key requires an owner credential profile");
  }
  if ((credential.kind === "ecdsa") !== (record.validator !== null)) {
    return inputInvalid("credential owner key validator does not match the credential kind");
  }
  const validator =
    record.validator === null ? null : inputAddress(record.validator, "credential owner validator");

  return Object.freeze({
    kind: credential.kind,
    publicMaterial: publicMaterial(credential),
    resolveValidator: (deployment: Readonly<KernelV4Deployment>) => {
      exactKernelDeployment(deployment);
      if (validator !== null) return validator;
      return resolvePinnedValidator(credential.kind);
    },
    signerModule: null,
    dummySignature: DUMMY[credential.kind],
    async sign(): Promise<`0x${string}`> {
      return runtimeFail(
        "kernel_runtime_signing_failed",
        "owner signing happens on the owner device, never in the application",
      );
    },
    async verify(): Promise<boolean> {
      return false;
    },
  });
}
