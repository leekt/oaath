import { ECDSA_SIGNER_CONTRACT } from "@zerodev/permissions";
import { DUMMY_ECDSA_SIG } from "@zerodev/sdk/constants";
import { concat, encodeAbiParameters, recoverMessageAddress } from "viem";
import {
  captureOperatorCredentialProfile,
  type EcdsaOperatorCredentialProfile,
} from "./identity-profile.js";
import { type CaptureContext, exactRecord } from "./internal/exact-record.js";

const ADDRESS = /^0x[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const SIGNATURE = /^0x[0-9a-f]{130}$/u;
const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const CANONICAL_SIGNER_CONTRACT = ECDSA_SIGNER_CONTRACT.toLowerCase() as `0x${string}`;
const CANONICAL_DUMMY_SIGNATURE = DUMMY_ECDSA_SIG.toLowerCase() as `0x${string}`;

export type EcdsaPermissionSignerErrorCode =
  | "ecdsa_permission_signer_input_invalid"
  | "ecdsa_permission_signer_capability_invalid"
  | "ecdsa_permission_signer_binding_mismatch"
  | "ecdsa_permission_signer_request_invalid"
  | "ecdsa_permission_signer_signing_failed";

export class OgpEcdsaPermissionSignerError extends Error {
  readonly code: EcdsaPermissionSignerErrorCode;

  constructor(code: EcdsaPermissionSignerErrorCode, message: string) {
    super(message);
    this.name = "OgpEcdsaPermissionSignerError";
    this.code = code;
  }
}

export interface EcdsaPermissionSignerCapability {
  readonly address: `0x${string}`;
  readonly signMessageHash: (request: Readonly<{ hash: `0x${string}` }>) => Promise<unknown>;
}

export interface EcdsaPermissionSignerRuntime {
  readonly profile: Readonly<EcdsaOperatorCredentialProfile>;
  readonly signerContractAddress: `0x${string}`;
  readonly signerData: `0x${string}`;
  readonly signerId: `0x${string}`;
  readonly dummySignature: `0x${string}`;
  readonly signMessageHash: (value: unknown) => Promise<`0x${string}`>;
}

interface CapturedSigner {
  readonly address: `0x${string}`;
  readonly signMessageHash: EcdsaPermissionSignerCapability["signMessageHash"];
}

function signerError(code: EcdsaPermissionSignerErrorCode, message: string): never {
  throw new OgpEcdsaPermissionSignerError(code, message);
}

function address(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value) || value === ZERO_ADDRESS) {
    return signerError(
      "ecdsa_permission_signer_capability_invalid",
      "ECDSA permission signer address is invalid",
    );
  }
  return value as `0x${string}`;
}

function captureSigner(
  value: unknown,
  expectedAddress: `0x${string}`,
  context: CaptureContext,
): Readonly<CapturedSigner> {
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["address", "signMessageHash"],
      "ECDSA permission signer capability",
      context,
      (message) => signerError("ecdsa_permission_signer_capability_invalid", message),
    );
  } catch (error) {
    if (error instanceof OgpEcdsaPermissionSignerError) throw error;
    return signerError(
      "ecdsa_permission_signer_capability_invalid",
      "ECDSA permission signer capability could not be captured safely",
    );
  }
  const signerAddress = address(record.address);
  if (signerAddress !== expectedAddress) {
    return signerError(
      "ecdsa_permission_signer_binding_mismatch",
      "ECDSA permission signer does not match the selected operator profile",
    );
  }
  if (typeof record.signMessageHash !== "function") {
    return signerError(
      "ecdsa_permission_signer_capability_invalid",
      "ECDSA permission signing capability is invalid",
    );
  }
  return Object.freeze({
    address: signerAddress,
    signMessageHash: record.signMessageHash as EcdsaPermissionSignerCapability["signMessageHash"],
  });
}

function requestHash(value: unknown): `0x${string}` {
  try {
    const record = exactRecord(
      value,
      ["hash"],
      "ECDSA permission signing request",
      new WeakSet(),
      (message) => signerError("ecdsa_permission_signer_request_invalid", message),
    );
    if (typeof record.hash !== "string" || !HASH.test(record.hash)) {
      return signerError(
        "ecdsa_permission_signer_request_invalid",
        "ECDSA permission signing hash must be a lowercase 32-byte value",
      );
    }
    return record.hash as `0x${string}`;
  } catch (error) {
    if (error instanceof OgpEcdsaPermissionSignerError) throw error;
    return signerError(
      "ecdsa_permission_signer_request_invalid",
      "ECDSA permission signing request could not be captured safely",
    );
  }
}

function normalizeSignature(value: unknown): `0x${string}` {
  if (typeof value !== "string" || !SIGNATURE.test(value)) {
    return signerError(
      "ecdsa_permission_signer_signing_failed",
      "ECDSA permission signature is invalid",
    );
  }
  const recoveryByte = value.slice(-2);
  let normalized = value;
  if (recoveryByte === "00") normalized = `${value.slice(0, -2)}1b`;
  else if (recoveryByte === "01") normalized = `${value.slice(0, -2)}1c`;
  else if (recoveryByte !== "1b" && recoveryByte !== "1c") {
    return signerError(
      "ecdsa_permission_signer_signing_failed",
      "ECDSA permission signature recovery byte is invalid",
    );
  }
  return normalized as `0x${string}`;
}

async function verifiedSignature(
  value: unknown,
  hash: `0x${string}`,
  expectedAddress: `0x${string}`,
): Promise<`0x${string}`> {
  const normalized = normalizeSignature(value);
  let recovered: string;
  try {
    recovered = await recoverMessageAddress({
      message: { raw: hash },
      signature: normalized,
    });
  } catch {
    return signerError(
      "ecdsa_permission_signer_signing_failed",
      "ECDSA permission signature could not be recovered",
    );
  }
  if (recovered.toLowerCase() !== expectedAddress) {
    return signerError(
      "ecdsa_permission_signer_signing_failed",
      "ECDSA permission signature does not match the selected operator",
    );
  }
  return normalized;
}

/**
 * Captures one chain-neutral ECDSA operator and proves its canonical Kernel 3.3
 * PermissionValidator signer identity. Permission composition owns policy and chain facts later.
 */
export async function createEcdsaPermissionSignerRuntime(
  value: unknown,
): Promise<Readonly<EcdsaPermissionSignerRuntime>> {
  const context: CaptureContext = new WeakSet();
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["profile", "signer"],
      "ECDSA permission signer runtime input",
      context,
      (message) => signerError("ecdsa_permission_signer_input_invalid", message),
    );
  } catch (error) {
    if (error instanceof OgpEcdsaPermissionSignerError) throw error;
    return signerError(
      "ecdsa_permission_signer_input_invalid",
      "ECDSA permission signer runtime input could not be captured safely",
    );
  }

  let capturedProfile: ReturnType<typeof captureOperatorCredentialProfile>;
  try {
    capturedProfile = captureOperatorCredentialProfile(record.profile, context, (message) =>
      signerError("ecdsa_permission_signer_input_invalid", message),
    );
  } catch (error) {
    if (error instanceof OgpEcdsaPermissionSignerError) throw error;
    return signerError(
      "ecdsa_permission_signer_input_invalid",
      "ECDSA permission signer profile could not be captured safely",
    );
  }
  if (capturedProfile.kind !== "ecdsa") {
    return signerError(
      "ecdsa_permission_signer_input_invalid",
      "Selected operator profile is not ECDSA",
    );
  }
  const profile = capturedProfile;
  const signer = captureSigner(record.signer, profile.address, context);
  const signerContractAddress = CANONICAL_SIGNER_CONTRACT;
  const signerData = profile.address;
  const signerId = encodeAbiParameters(
    [{ name: "signerData", type: "bytes" }],
    [concat([CANONICAL_SIGNER_CONTRACT, profile.address])],
  ).toLowerCase() as `0x${string}`;
  const dummySignature = CANONICAL_DUMMY_SIGNATURE;

  return Object.freeze({
    profile,
    signerContractAddress,
    signerData,
    signerId,
    dummySignature,
    async signMessageHash(request: unknown) {
      const hash = requestHash(request);
      try {
        return await verifiedSignature(
          await Reflect.apply(signer.signMessageHash, undefined, [Object.freeze({ hash })]),
          hash,
          profile.address,
        );
      } catch (error) {
        if (error instanceof OgpEcdsaPermissionSignerError) throw error;
        return signerError(
          "ecdsa_permission_signer_signing_failed",
          "ECDSA permission signing failed",
        );
      }
    },
  });
}
