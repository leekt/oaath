import { signerToEcdsaValidator } from "@zerodev/ecdsa-validator";
import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import type { KernelValidator } from "@zerodev/sdk/types";
import type { Client } from "viem";
import { entryPoint07Address } from "viem/account-abstraction";
import type { EcdsaSigningKey, KernelSigner } from "./types.js";

/** Adapt an ECDSA signing key to the shared Kernel signer interface. */
export function toEcdsaKernelSigner(
  signer: EcdsaSigningKey,
): KernelSigner<KernelValidator<"ECDSAValidator">> {
  return Object.freeze({
    validator(client: Client) {
      return signerToEcdsaValidator(client, {
        signer,
        entryPoint: { version: "0.7", address: entryPoint07Address },
        kernelVersion: KERNEL_V3_3,
      });
    },
  });
}
