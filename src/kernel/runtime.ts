import { KERNEL_V3_3 } from "@zerodev/sdk/constants";
import type { Client } from "viem";
import {
  type Kernel33Validator,
  type KernelSigner,
  OgpKernelSignerError,
} from "../signer/types.js";

const ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const VALIDATOR_METHODS = [
  "getIdentifier",
  "getEnableData",
  "getNonceKey",
  "getStubSignature",
  "signUserOperation",
  "isEnabled",
] as const;

export interface CreateKernelRuntimeInput<Validator extends Kernel33Validator = Kernel33Validator> {
  readonly client: Client;
  readonly signer: KernelSigner<Validator>;
}

function fail(
  code: "kernel_signer_invalid" | "kernel_validator_incompatible" | "kernel_validator_unavailable",
  message: string,
): never {
  throw new OgpKernelSignerError(code, message);
}

/** Resolve one signer module and capture its Kernel 3.3 validator output. */
export async function createKernelRuntime<Validator extends Kernel33Validator>(
  value: CreateKernelRuntimeInput<Validator>,
): Promise<Readonly<Validator>> {
  let createValidator: KernelSigner<Validator>["validator"];
  try {
    createValidator = value.signer.validator;
  } catch {
    return fail("kernel_signer_invalid", "Kernel signer could not be read");
  }
  if (typeof createValidator !== "function") {
    return fail("kernel_signer_invalid", "Kernel signer validator factory is invalid");
  }

  let validator: Validator;
  try {
    validator = await Reflect.apply(createValidator, value.signer, [value.client]);
  } catch (error) {
    if (error instanceof OgpKernelSignerError) throw error;
    return fail("kernel_validator_unavailable", "Kernel validator could not be created");
  }

  try {
    if (
      !validator ||
      typeof validator !== "object" ||
      !ADDRESS.test(validator.address) ||
      validator.supportedKernelVersions !== KERNEL_V3_3 ||
      (validator.validatorType !== "SECONDARY" &&
        validator.validatorType !== "PERMISSION" &&
        validator.validatorType !== "EIP7702") ||
      VALIDATOR_METHODS.some((method) => typeof validator[method] !== "function")
    ) {
      return fail(
        "kernel_validator_incompatible",
        "Kernel validator is incompatible with Kernel 3.3",
      );
    }
    return Object.freeze(validator);
  } catch (error) {
    if (error instanceof OgpKernelSignerError) throw error;
    return fail("kernel_validator_incompatible", "Kernel validator could not be captured safely");
  }
}
