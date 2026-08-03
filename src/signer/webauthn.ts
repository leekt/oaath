import { PasskeyValidatorContractVersion, toPasskeyValidator } from "@zerodev/passkey-validator";
import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import type { KernelValidator } from "@zerodev/sdk/types";
import { type Client, toHex } from "viem";
import { entryPoint07Address } from "viem/account-abstraction";
import { exactRecord } from "../internal/exact-record.js";
import { isP256PublicKeyEncoding } from "../internal/p256-validator.js";
import { type KernelSigner, OgpKernelSignerError, type WebAuthnSigningKey } from "./types.js";

const HASH = /^0x[0-9a-f]{64}$/u;

function captureSigningKey(value: WebAuthnSigningKey): Readonly<WebAuthnSigningKey> {
  const fail = (message: string): never => {
    throw new OgpKernelSignerError("kernel_signer_invalid", message);
  };
  let record: Record<string, unknown>;
  try {
    record = exactRecord(
      value,
      ["pubX", "pubY", "authenticatorId", "authenticatorIdHash", "rpID", "signMessageCallback"],
      "WebAuthn signing key",
      new WeakSet(),
      fail,
    );
  } catch (error) {
    if (error instanceof OgpKernelSignerError) throw error;
    return fail("WebAuthn signing key could not be captured safely");
  }
  if (typeof record.pubX !== "bigint" || typeof record.pubY !== "bigint") {
    return fail("WebAuthn public key is invalid");
  }
  const publicKey = `0x04${toHex(record.pubX, { size: 32 }).slice(2)}${toHex(record.pubY, {
    size: 32,
  }).slice(2)}`;
  if (!isP256PublicKeyEncoding(publicKey)) return fail("WebAuthn public key is invalid");
  if (
    typeof record.authenticatorId !== "string" ||
    typeof record.authenticatorIdHash !== "string" ||
    !HASH.test(record.authenticatorIdHash) ||
    typeof record.rpID !== "string" ||
    typeof record.signMessageCallback !== "function"
  ) {
    return fail("WebAuthn signing key is invalid");
  }
  return Object.freeze({
    pubX: record.pubX,
    pubY: record.pubY,
    authenticatorId: record.authenticatorId,
    authenticatorIdHash: record.authenticatorIdHash as `0x${string}`,
    rpID: record.rpID,
    signMessageCallback: record.signMessageCallback as WebAuthnSigningKey["signMessageCallback"],
  });
}

/** Adapt a WebAuthn signing key to the shared Kernel signer interface. */
export function toWebAuthnKernelSigner(
  value: WebAuthnSigningKey,
): KernelSigner<KernelValidator<"WebAuthnValidator">> {
  const signer = captureSigningKey(value);
  return Object.freeze({
    validator(client: Client) {
      return toPasskeyValidator(client, {
        webAuthnKey: signer,
        entryPoint: { version: "0.7", address: entryPoint07Address },
        kernelVersion: KERNEL_V3_3,
        validatorContractVersion: PasskeyValidatorContractVersion.V0_0_3_PATCHED,
      });
    },
  });
}
