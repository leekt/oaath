import { p256 } from "@noble/curves/nist.js";
import {
  type CaptureContext,
  type CaptureFailure,
  captureRecord,
  exactCapturedRecord,
  exactRecord,
} from "./internal/exact-record.js";
import { getKernelRuntimeCapability } from "./kernel-runtime-capabilities.js";

export const OGP_OWNER_CREDENTIAL_PROFILE_VERSION = "ogp.owner-credential-profile/v1" as const;
export const OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION =
  "ogp.operator-credential-profile/v1" as const;
export const OGP_KERNEL_ACCOUNT_PROFILE_VERSION = "ogp.kernel-account-profile/v1" as const;

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const P256_PUBLIC_KEY = /^0x04[0-9a-f]{128}$/u;
const DECIMAL_UINT = /^(?:0|[1-9][0-9]{0,77})$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const MAX_UINT256 = (1n << 256n) - 1n;

export type OwnerCredentialKind = "ecdsa" | "p256" | "webauthn";
export type OperatorCredentialKind = "ecdsa" | "webauthn";

export interface EcdsaOwnerCredentialProfile {
  readonly version: typeof OGP_OWNER_CREDENTIAL_PROFILE_VERSION;
  readonly kind: "ecdsa";
  readonly address: `0x${string}`;
}

export interface P256OwnerCredentialProfile {
  readonly version: typeof OGP_OWNER_CREDENTIAL_PROFILE_VERSION;
  readonly kind: "p256";
  readonly publicKey: `0x${string}`;
}

export interface WebAuthnOwnerCredentialProfile {
  readonly version: typeof OGP_OWNER_CREDENTIAL_PROFILE_VERSION;
  readonly kind: "webauthn";
  readonly publicKey: `0x${string}`;
  readonly authenticatorIdHash: `0x${string}`;
}

export type OwnerCredentialProfile =
  | EcdsaOwnerCredentialProfile
  | P256OwnerCredentialProfile
  | WebAuthnOwnerCredentialProfile;

export interface EcdsaOperatorCredentialProfile {
  readonly version: typeof OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION;
  readonly kind: "ecdsa";
  readonly address: `0x${string}`;
}

export interface WebAuthnOperatorCredentialProfile {
  readonly version: typeof OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION;
  readonly kind: "webauthn";
  readonly publicKey: `0x${string}`;
  readonly authenticatorIdHash: `0x${string}`;
}

export type OperatorCredentialProfile =
  | EcdsaOperatorCredentialProfile
  | WebAuthnOperatorCredentialProfile;

export interface KernelAccountProfile {
  readonly version: typeof OGP_KERNEL_ACCOUNT_PROFILE_VERSION;
  readonly kind: "kernel";
  readonly accountIndex: string;
  readonly kernelVersion: "0.3.3";
  readonly factoryRoute: "kernel_factory" | "meta_factory";
  readonly entryPoint: Readonly<{ version: "0.7" }>;
  readonly ownerCredential: Readonly<OwnerCredentialProfile>;
}

export interface KernelAccountActionInput {
  readonly chainId: number;
  readonly accountIndex: string;
  readonly kernelVersion: "0.3.3";
  readonly factoryRoute: KernelAccountProfile["factoryRoute"];
  readonly entryPointVersion: "0.7";
  readonly ownerCredential: Readonly<OwnerCredentialProfile>;
}

export type CredentialRuntimeCapability =
  | "owner_ecdsa"
  | "owner_p256"
  | "owner_webauthn"
  | "permission_signer_ecdsa"
  | "permission_signer_webauthn";

export type CredentialRuntimeDiagnosis<
  Profile extends OwnerCredentialProfile | OperatorCredentialProfile =
    | OwnerCredentialProfile
    | OperatorCredentialProfile,
> =
  | Readonly<{
      status: "available";
      capability: CredentialRuntimeCapability;
      profile: Readonly<Profile>;
    }>
  | Readonly<{
      status: "absent";
      capability: CredentialRuntimeCapability;
      profile: Readonly<Profile>;
      reason: "required_package_not_installed";
    }>
  | Readonly<{
      status: "unreadable";
      capability: CredentialRuntimeCapability;
      profile: Readonly<Profile>;
      reason: "runtime_capability_evidence_unreadable";
    }>
  | Readonly<{
      status: "unsupported";
      capability: CredentialRuntimeCapability;
      profile: Readonly<Profile>;
      reason: "first_party_profile_unproven";
    }>;

export type IdentityProfileErrorCode =
  | "owner_credential_profile_invalid"
  | "operator_credential_profile_invalid"
  | "kernel_account_profile_invalid"
  | "kernel_account_action_input_invalid";

export class OgpIdentityProfileError extends Error {
  readonly code: IdentityProfileErrorCode;

  constructor(code: IdentityProfileErrorCode, message: string) {
    super(message);
    this.name = "OgpIdentityProfileError";
    this.code = code;
  }
}

function invalid(code: IdentityProfileErrorCode, message: string): never {
  throw new OgpIdentityProfileError(code, message);
}

function address(value: unknown, label: string, fail: CaptureFailure): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return fail(`${label} must be a nonzero lowercase address`);
  }
  return value as `0x${string}`;
}

function hash(value: unknown, label: string, fail: CaptureFailure): `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) {
    return fail(`${label} must be a lowercase 32-byte hash`);
  }
  return value as `0x${string}`;
}

function p256PublicKey(value: unknown, label: string, fail: CaptureFailure): `0x${string}` {
  if (typeof value !== "string" || !P256_PUBLIC_KEY.test(value)) {
    return fail(`${label} must be a lowercase uncompressed P-256 public key`);
  }
  try {
    p256.ProjectivePoint.fromHex(value.slice(2));
  } catch {
    return fail(`${label} must be an on-curve P-256 public key`);
  }
  return value as `0x${string}`;
}

function accountIndex(value: unknown, fail: CaptureFailure): string {
  if (typeof value !== "string" || !DECIMAL_UINT.test(value) || BigInt(value) > MAX_UINT256) {
    return fail("Kernel account index must be a canonical decimal uint256 string");
  }
  return value;
}

function captureOwnerCredential(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OwnerCredentialProfile> {
  const captured = captureRecord(value, "owner credential profile", context, fail);
  const keys =
    captured.kind === "ecdsa"
      ? ["version", "kind", "address"]
      : captured.kind === "p256"
        ? ["version", "kind", "publicKey"]
        : captured.kind === "webauthn"
          ? ["version", "kind", "publicKey", "authenticatorIdHash"]
          : ["version", "kind"];
  const record = exactCapturedRecord(captured, keys, "owner credential profile", fail);
  if (record.version !== OGP_OWNER_CREDENTIAL_PROFILE_VERSION) {
    return fail("owner credential profile version is unsupported");
  }
  if (record.kind === "ecdsa") {
    return Object.freeze({
      version: OGP_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: address(record.address, "owner credential address", fail),
    });
  }
  if (record.kind === "p256") {
    return Object.freeze({
      version: OGP_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "p256",
      publicKey: p256PublicKey(record.publicKey, "owner credential publicKey", fail),
    });
  }
  if (record.kind === "webauthn") {
    return Object.freeze({
      version: OGP_OWNER_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn",
      publicKey: p256PublicKey(record.publicKey, "owner credential publicKey", fail),
      authenticatorIdHash: hash(
        record.authenticatorIdHash,
        "owner credential authenticatorIdHash",
        fail,
      ),
    });
  }
  return fail("owner credential kind is unsupported");
}

function captureOperatorCredential(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OperatorCredentialProfile> {
  const captured = captureRecord(value, "operator credential profile", context, fail);
  const keys =
    captured.kind === "ecdsa"
      ? ["version", "kind", "address"]
      : captured.kind === "webauthn"
        ? ["version", "kind", "publicKey", "authenticatorIdHash"]
        : ["version", "kind"];
  const record = exactCapturedRecord(captured, keys, "operator credential profile", fail);
  if (record.version !== OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION) {
    return fail("operator credential profile version is unsupported");
  }
  if (record.kind === "ecdsa") {
    return Object.freeze({
      version: OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION,
      kind: "ecdsa",
      address: address(record.address, "operator credential address", fail),
    });
  }
  if (record.kind === "webauthn") {
    return Object.freeze({
      version: OGP_OPERATOR_CREDENTIAL_PROFILE_VERSION,
      kind: "webauthn",
      publicKey: p256PublicKey(record.publicKey, "operator credential publicKey", fail),
      authenticatorIdHash: hash(
        record.authenticatorIdHash,
        "operator credential authenticatorIdHash",
        fail,
      ),
    });
  }
  return fail("operator credential kind is unsupported");
}

export function captureOwnerCredentialProfile(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OwnerCredentialProfile> {
  return captureOwnerCredential(value, context, fail);
}

export function captureOperatorCredentialProfile(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<OperatorCredentialProfile> {
  return captureOperatorCredential(value, context, fail);
}

export function captureKernelAccountProfile(
  value: unknown,
  context: CaptureContext,
  fail: CaptureFailure,
): Readonly<KernelAccountProfile> {
  const record = exactRecord(
    value,
    [
      "version",
      "kind",
      "accountIndex",
      "kernelVersion",
      "factoryRoute",
      "entryPoint",
      "ownerCredential",
    ],
    "Kernel account profile",
    context,
    fail,
  );
  if (record.version !== OGP_KERNEL_ACCOUNT_PROFILE_VERSION || record.kind !== "kernel") {
    return fail("Kernel account profile version or kind is unsupported");
  }
  if (record.kernelVersion !== "0.3.3") {
    return fail("Kernel account version is unsupported");
  }
  if (record.factoryRoute !== "kernel_factory" && record.factoryRoute !== "meta_factory") {
    return fail("Kernel account factory route is unsupported");
  }
  const entryPoint = exactRecord(
    record.entryPoint,
    ["version"],
    "Kernel account EntryPoint profile",
    context,
    fail,
  );
  if (entryPoint.version !== "0.7") return fail("Kernel account EntryPoint is unsupported");
  return Object.freeze({
    version: OGP_KERNEL_ACCOUNT_PROFILE_VERSION,
    kind: "kernel",
    accountIndex: accountIndex(record.accountIndex, fail),
    kernelVersion: "0.3.3",
    factoryRoute: record.factoryRoute,
    entryPoint: Object.freeze({ version: "0.7" }),
    ownerCredential: captureOwnerCredentialProfile(record.ownerCredential, context, fail),
  });
}

export function parseOwnerCredentialProfile(value: unknown): Readonly<OwnerCredentialProfile> {
  try {
    return captureOwnerCredentialProfile(value, new WeakSet(), (message) =>
      invalid("owner_credential_profile_invalid", message),
    );
  } catch {
    return invalid(
      "owner_credential_profile_invalid",
      "owner credential profile could not be captured safely",
    );
  }
}

export function parseOperatorCredentialProfile(
  value: unknown,
): Readonly<OperatorCredentialProfile> {
  try {
    return captureOperatorCredentialProfile(value, new WeakSet(), (message) =>
      invalid("operator_credential_profile_invalid", message),
    );
  } catch {
    return invalid(
      "operator_credential_profile_invalid",
      "operator credential profile could not be captured safely",
    );
  }
}

export function parseKernelAccountProfile(value: unknown): Readonly<KernelAccountProfile> {
  try {
    return captureKernelAccountProfile(value, new WeakSet(), (message) =>
      invalid("kernel_account_profile_invalid", message),
    );
  } catch {
    return invalid(
      "kernel_account_profile_invalid",
      "Kernel account profile could not be captured safely",
    );
  }
}

export function createKernelAccountActionInput(
  profileValue: unknown,
  chainIdValue: unknown,
): Readonly<KernelAccountActionInput> {
  try {
    const profile = parseKernelAccountProfile(profileValue);
    if (
      typeof chainIdValue !== "number" ||
      !Number.isSafeInteger(chainIdValue) ||
      chainIdValue < 1
    ) {
      return invalid("kernel_account_action_input_invalid", "action chainId must be positive");
    }
    return Object.freeze({
      chainId: chainIdValue,
      accountIndex: profile.accountIndex,
      kernelVersion: profile.kernelVersion,
      factoryRoute: profile.factoryRoute,
      entryPointVersion: profile.entryPoint.version,
      ownerCredential: profile.ownerCredential,
    });
  } catch {
    return invalid(
      "kernel_account_action_input_invalid",
      "Kernel account action input could not be captured safely",
    );
  }
}

function diagnose<Profile extends OwnerCredentialProfile | OperatorCredentialProfile>(
  profile: Readonly<Profile>,
  capability: CredentialRuntimeCapability,
): CredentialRuntimeDiagnosis<Profile> {
  const runtime = getKernelRuntimeCapability(capability);
  if (runtime.status === "available") {
    return Object.freeze({ status: "available", capability, profile });
  }
  if (runtime.reason === "package_not_installed") {
    return Object.freeze({
      status: "absent",
      capability,
      profile,
      reason: "required_package_not_installed",
    });
  }
  if (runtime.reason === "distinct_profile_unproven") {
    return Object.freeze({
      status: "unsupported",
      capability,
      profile,
      reason: "first_party_profile_unproven",
    });
  }
  return Object.freeze({
    status: "unreadable",
    capability,
    profile,
    reason: "runtime_capability_evidence_unreadable",
  });
}

export function diagnoseOwnerCredential(
  value: unknown,
): CredentialRuntimeDiagnosis<OwnerCredentialProfile> {
  const profile = parseOwnerCredentialProfile(value);
  const capability = `owner_${profile.kind}` as const;
  return diagnose(profile, capability);
}

export function diagnoseOperatorCredential(
  value: unknown,
): CredentialRuntimeDiagnosis<OperatorCredentialProfile> {
  const profile = parseOperatorCredentialProfile(value);
  const capability = `permission_signer_${profile.kind}` as const;
  return diagnose(profile, capability);
}

export function sameOwnerCredentialProfile(
  left: OwnerCredentialProfile,
  right: OwnerCredentialProfile,
): boolean {
  if (left.version !== right.version || left.kind !== right.kind) return false;
  if (left.kind === "ecdsa" && right.kind === "ecdsa") return left.address === right.address;
  if (left.kind === "p256" && right.kind === "p256") return left.publicKey === right.publicKey;
  return (
    left.kind === "webauthn" &&
    right.kind === "webauthn" &&
    left.publicKey === right.publicKey &&
    left.authenticatorIdHash === right.authenticatorIdHash
  );
}

export function sameOperatorCredentialProfile(
  left: OperatorCredentialProfile,
  right: OperatorCredentialProfile,
): boolean {
  if (left.version !== right.version || left.kind !== right.kind) return false;
  if (left.kind === "ecdsa" && right.kind === "ecdsa") return left.address === right.address;
  return (
    left.kind === "webauthn" &&
    right.kind === "webauthn" &&
    left.publicKey === right.publicKey &&
    left.authenticatorIdHash === right.authenticatorIdHash
  );
}

export function sameKernelAccountProfile(
  left: KernelAccountProfile,
  right: KernelAccountProfile,
): boolean {
  return (
    left.version === right.version &&
    left.kind === right.kind &&
    left.accountIndex === right.accountIndex &&
    left.kernelVersion === right.kernelVersion &&
    left.factoryRoute === right.factoryRoute &&
    left.entryPoint.version === right.entryPoint.version &&
    sameOwnerCredentialProfile(left.ownerCredential, right.ownerCredential)
  );
}
