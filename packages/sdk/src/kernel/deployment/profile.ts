import type { KernelV4Deployment } from "../../kernel-v4.js";
import type { KernelV33Deployment } from "./v33.js";

type SupportedKernelDeployment = KernelV4Deployment | KernelV33Deployment;

/**
 * The two supported Kernel contract versions, sharing the key/operator axes.
 * `KernelDeployment<"0.3.3">` selects one version by the profile's own
 * `kernelVersion` discriminant; the default is either version.
 */
export type KernelDeployment<
  Version extends
    SupportedKernelDeployment["kernelVersion"] = SupportedKernelDeployment["kernelVersion"],
> = Extract<SupportedKernelDeployment, { readonly kernelVersion: Version }>;
