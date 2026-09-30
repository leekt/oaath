import { describe, expect, expectTypeOf, it } from "vitest";
import {
  type CreateKernelRuntimeInput,
  createKernelRuntime,
  type KernelDeployment,
  type KernelRuntime,
  kernelDeployment,
} from "../src/kernel.js";
import type {
  CreateKernelRuntimeInput as AnyVersionInput,
  KernelRuntime as AnyVersionRuntime,
} from "../src/kernel/types.js";

// Type-level proof: the public entry names each version's shapes through the
// deployment's own `kernelVersion` discriminant, so consumers need no casts.
function composeV33(input: CreateKernelRuntimeInput<"0.3.3">): KernelRuntime<"0.3.3"> {
  return createKernelRuntime(input);
}
function composeV4(input: CreateKernelRuntimeInput<"0.4.0">): KernelRuntime<"0.4.0"> {
  return createKernelRuntime(input);
}

describe("version-selected public Kernel types", () => {
  it("selects the Kernel 0.3.3 deployment, runtime and input by version", () => {
    const deployment: KernelDeployment<"0.3.3"> = kernelDeployment({
      chainId: 143,
      kernelVersion: "0.3.3",
    });
    expect(deployment.ecdsaValidator).toMatch(/^0x[0-9a-f]{40}$/u);
    expectTypeOf<KernelDeployment<"0.3.3">["kernelVersion"]>().toEqualTypeOf<"0.3.3">();
    expectTypeOf<KernelDeployment<"0.4.0">["kernelVersion"]>().toEqualTypeOf<"0.4.0">();
    expectTypeOf<CreateKernelRuntimeInput<"0.3.3">["deployment"]>().toEqualTypeOf<
      Readonly<KernelDeployment<"0.3.3">>
    >();
    expectTypeOf<KernelRuntime<"0.3.3">["deployment"]>().toEqualTypeOf<
      Readonly<KernelDeployment<"0.3.3">>
    >();
    expectTypeOf<KernelRuntime<"0.4.0">["deployment"]>().toEqualTypeOf<
      Readonly<KernelDeployment<"0.4.0">>
    >();
    expectTypeOf<
      NonNullable<Parameters<KernelRuntime<"0.3.3">["prepareOperation"]>[0]["mode"]>
    >().toEqualTypeOf<"standard" | "enable">();
    expectTypeOf<
      Awaited<ReturnType<KernelRuntime<"0.3.3">["bindAccount"]>>
    >().toHaveProperty("rootValidator");
    expectTypeOf(composeV33).toBeFunction();
    expectTypeOf(composeV4).toBeFunction();
  });

  it("keeps either version as the default", () => {
    expectTypeOf<KernelDeployment>().toEqualTypeOf<
      KernelDeployment<"0.3.3"> | KernelDeployment<"0.4.0">
    >();
    expectTypeOf<KernelRuntime>().toEqualTypeOf<AnyVersionRuntime>();
    expectTypeOf<CreateKernelRuntimeInput>().toEqualTypeOf<AnyVersionInput>();
    // @ts-expect-error a Kernel 0.4.0 deployment is not a Kernel 0.3.3 deployment
    const wrong: KernelDeployment<"0.3.3"> = kernelDeployment({ chainId: 143 });
    expect(wrong.kernelVersion).toBe("0.4.0");
  });
});
