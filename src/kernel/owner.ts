import type { Kernel33Validator } from "../signer/types.js";
import { type CreateKernelRuntimeInput, createKernelRuntime } from "./runtime.js";

/** Create a Kernel 3.3 validator for ZeroDev's `sudo` owner slot. */
export function createKernelOwner<Validator extends Kernel33Validator>(
  value: CreateKernelRuntimeInput<Validator>,
): Promise<Readonly<Validator>> {
  return createKernelRuntime(value);
}
