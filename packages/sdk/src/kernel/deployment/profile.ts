import type { KernelV4Deployment } from "../../kernel-v4.js";
import type { KernelV33Deployment } from "./v33.js";

/** The two supported Kernel contract versions, sharing the key/operator axes. */
export type KernelDeployment = KernelV4Deployment | KernelV33Deployment;
