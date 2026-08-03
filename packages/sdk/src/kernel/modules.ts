/**
 * Pinned ERC-7579 module deployments per Kernel v4 chain and axis. Contract
 * addresses live here and in kernel-v4.ts only, never duplicated across key,
 * operator, or hook files. An unbound axis fails closed; never add an address
 * that has not been reviewed and proven on the target chain.
 *
 * @author taek <leekt216@gmail.com>
 */
import {
  type KernelV4Deployment,
  type KernelV4SupportedChainId,
  kernelV4Deployment,
} from "../kernel-v4.js";
import { inputInvalid, runtimeFail } from "./internal.js";
import type { KernelKeyKind } from "./types.js";

/**
 * Validator modules bound per chain and key kind. Kernel v4 ships no reviewed
 * raw P-256 or WebAuthn validator deployment yet, so both kinds resolve to
 * absent and every composition using them fails closed.
 */
const PINNED_VALIDATORS: Readonly<
  Record<KernelV4SupportedChainId, Readonly<Partial<Record<KernelKeyKind, `0x${string}`>>>>
> = Object.freeze({
  46630: Object.freeze({}),
  421614: Object.freeze({}),
  11155111: Object.freeze({}),
});

/**
 * Policy/hook modules bound per chain. Kernel v4 ships no reviewed OAAth call,
 * value, expiry, or operation-limit module yet, so composed policies model and
 * encode their configuration but never materialize.
 */
const PINNED_HOOK_MODULES: Readonly<Record<KernelV4SupportedChainId, `0x${string}` | undefined>> =
  Object.freeze({
    46630: undefined,
    421614: undefined,
    11155111: undefined,
  });

/** Accepts only the exact frozen deployment profile owned by kernel-v4.ts. */
export function exactKernelDeployment(value: unknown): Readonly<KernelV4Deployment> {
  let chainId: unknown;
  try {
    chainId = (value as { readonly chainId?: unknown } | null | undefined)?.chainId;
  } catch {
    return inputInvalid("Kernel deployment profile is invalid");
  }
  const deployment = kernelV4Deployment(chainId);
  if (deployment !== value) {
    return inputInvalid("Kernel deployment profile is not the pinned Kernel v4 profile");
  }
  return deployment;
}

/**
 * The reviewed validator module bound to one key kind, or null when none is.
 * Both the composition factory and capability diagnosis read the registry here,
 * so an unbound axis can never read available on one path and fail on the other.
 */
export function pinnedValidatorModule(
  deployment: Readonly<KernelV4Deployment>,
  kind: KernelKeyKind,
): `0x${string}` | null {
  return PINNED_VALIDATORS[deployment.chainId][kind] ?? null;
}

/** The reviewed policy hook module bound to this chain, or null when none is. */
export function pinnedHookModule(deployment: Readonly<KernelV4Deployment>): `0x${string}` | null {
  return PINNED_HOOK_MODULES[deployment.chainId] ?? null;
}

/** Resolves the reviewed validator module for one key kind, or fails closed. */
export function resolvePinnedValidator(
  deployment: Readonly<KernelV4Deployment>,
  kind: KernelKeyKind,
): `0x${string}` {
  return (
    pinnedValidatorModule(deployment, kind) ??
    runtimeFail(
      "kernel_runtime_validator_unavailable",
      `Kernel v4 has no reviewed ${kind} validator module deployment on this chain`,
    )
  );
}

/**
 * Resolves the module that enforces a composed policy, or fails closed. The
 * policy configuration itself is fully modelled and encoded by
 * composeKernelHooks; only its on-chain materialization is unavailable.
 */
export function resolveHookModule(deployment: Readonly<KernelV4Deployment>): `0x${string}` {
  return (
    pinnedHookModule(deployment) ??
    runtimeFail(
      "kernel_runtime_hook_unavailable",
      "Kernel v4 has no reviewed policy hook module deployment on this chain",
    )
  );
}
