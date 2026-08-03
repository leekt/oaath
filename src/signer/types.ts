import type { KernelValidator, Signer } from "@zerodev/sdk/types";
import type { WebAuthnKey } from "@zerodev/webauthn-key";
import type { Client } from "viem";

export type Kernel33Validator<Name extends string = string> = KernelValidator<Name>;

/** A signer module that adapts one credential to a Kernel 3.3 validator. */
export interface KernelSigner<Validator extends Kernel33Validator = Kernel33Validator> {
  readonly validator: (client: Client) => Promise<Validator>;
}

export type EcdsaSigningKey = Signer;

export interface P256SigningKey {
  readonly publicKey: `0x${string}`;
  readonly signMessageHash: (request: Readonly<{ hash: `0x${string}` }>) => Promise<unknown>;
}

export type WebAuthnSigningKey = WebAuthnKey & Required<Pick<WebAuthnKey, "signMessageCallback">>;

export type KernelSignerErrorCode =
  | "kernel_signer_invalid"
  | "kernel_signing_failed"
  | "kernel_validator_incompatible"
  | "kernel_validator_unavailable";

export class OgpKernelSignerError extends Error {
  readonly code: KernelSignerErrorCode;

  constructor(code: KernelSignerErrorCode, message: string) {
    super(message);
    this.name = "OgpKernelSignerError";
    this.code = code;
  }
}
