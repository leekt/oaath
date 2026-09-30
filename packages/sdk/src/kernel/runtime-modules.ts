/**
 * The OAAth runtime modules a chain must carry before OAAth grants can use it:
 * the WebAuthn permission signer, the fixed-window RateLimitPolicy, the OAAth
 * validity policy, CallPolicy, operation limit, ECDSA signer, and P-256 verifier. This
 * file owns two facts about them: whether one is present on a chain
 * (observeRuntimeModule, shared with createKernelRuntime's session bind) and
 * the exact zero-salt CREATE2 transaction that deploys it (shared with
 * `oaath deploy-runtime`).
 *
 * Status vocabulary, closed and fail-closed:
 *
 * - `present`: the address carries exactly the pinned runtime code hash.
 * - `missing`: the address provably carries no code, so the prepared
 *   deployment transaction is the remediation.
 * - `mismatch`: the address carries other code. It is never `present`, and it
 *   is distinct from `missing` because deploying cannot fix it: the CREATE2
 *   address is already occupied.
 * - `unreadable`: a read threw, returned a malformed or contradictory value, or
 *   the reads capability is bound to another chain. Never reported as
 *   `missing`.
 *
 * @author taek <leekt216@gmail.com>
 */
import { keccak256 } from "viem";
import { kernelV4Deployment } from "../kernel-v4.js";
import type { KernelReads } from "./deployment/account.js";
import { exactInput, inputCapability, inputInvalid, isBytes } from "./internal.js";
import {
  KERNEL_P256_VERIFIER,
  KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH,
  KERNEL_WEBAUTHN_SIGNER,
  KERNEL_WEBAUTHN_SIGNER_RUNTIME_CODE_HASH,
  OAATH_KERNEL_RATE_LIMIT_POLICY,
  OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH,
  OAATH_KERNEL_V4_VALIDITY_POLICY,
  OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
  resolvePinnedSigner,
  resolvePolicyModule,
} from "./modules.js";
import {
  CALL_POLICY_DEPLOYMENT_INPUT,
  ECDSA_SIGNER_DEPLOYMENT_INPUT,
  OPERATION_LIMIT_POLICY_DEPLOYMENT_INPUT,
  P256_VERIFIER_DEPLOYMENT_INPUT,
  RATE_LIMIT_POLICY_DEPLOYMENT_INPUT,
  VALIDITY_POLICY_DEPLOYMENT_INPUT,
  WEBAUTHN_SIGNER_DEPLOYMENT_INPUT,
} from "./runtime-module-inputs.js";

export type KernelRuntimeModule =
  | "webauthn_signer"
  | "rate_limit_policy"
  | "validity_policy"
  | "p256_verifier"
  | "call_policy"
  | "operation_limit_policy"
  | "ecdsa_signer";

export type KernelRuntimeModuleStatus = "present" | "missing" | "mismatch" | "unreadable";

export interface KernelRuntimeModuleReadiness {
  readonly module: KernelRuntimeModule;
  readonly address: `0x${string}`;
  readonly status: KernelRuntimeModuleStatus;
  /** Whether OAAth supplies the deployment transaction; this is not source ownership. */
  readonly deployment: "oaath" | "external";
}

export interface KernelRuntimeReadinessInput {
  readonly chainId: number;
  readonly reads: KernelReads;
}

export interface KernelRuntimeReadiness {
  readonly chainId: number;
  /** One entry per runtime module, in a fixed order. */
  readonly modules: readonly Readonly<KernelRuntimeModuleReadiness>[];
}

export interface PrepareRuntimeModuleDeploymentInput {
  readonly chainId: number;
  readonly module: KernelRuntimeModule;
}

/** The exact transaction that deploys one runtime module through the CREATE2 deployer. */
export interface KernelRuntimeModuleDeployment {
  readonly module: KernelRuntimeModule;
  /** The address the module lands on. */
  readonly address: `0x${string}`;
  /** The deployment profile's CREATE2 deployer. */
  readonly to: `0x${string}`;
  /** Zero salt followed by the module's pinned creation code. */
  readonly data: `0x${string}`;
  readonly value: bigint;
  readonly expectedRuntimeCodeHash: `0x${string}`;
}

type RuntimeModuleRow = Readonly<{
  address: `0x${string}`;
  runtimeCodeHash: `0x${string}`;
  deploymentInput: `0x${string}`;
}>;

const RUNTIME_MODULES: Readonly<Record<KernelRuntimeModule, RuntimeModuleRow>> = Object.freeze({
  webauthn_signer: Object.freeze({
    address: KERNEL_WEBAUTHN_SIGNER,
    runtimeCodeHash: KERNEL_WEBAUTHN_SIGNER_RUNTIME_CODE_HASH,
    deploymentInput: WEBAUTHN_SIGNER_DEPLOYMENT_INPUT,
  }),
  rate_limit_policy: Object.freeze({
    address: OAATH_KERNEL_RATE_LIMIT_POLICY,
    runtimeCodeHash: OAATH_KERNEL_RATE_LIMIT_POLICY_RUNTIME_CODE_HASH,
    deploymentInput: RATE_LIMIT_POLICY_DEPLOYMENT_INPUT,
  }),
  validity_policy: Object.freeze({
    address: OAATH_KERNEL_V4_VALIDITY_POLICY,
    runtimeCodeHash: OAATH_KERNEL_V4_VALIDITY_POLICY_RUNTIME_CODE_HASH,
    deploymentInput: VALIDITY_POLICY_DEPLOYMENT_INPUT,
  }),
  p256_verifier: Object.freeze({
    address: KERNEL_P256_VERIFIER,
    runtimeCodeHash: KERNEL_P256_VERIFIER_RUNTIME_CODE_HASH,
    deploymentInput: P256_VERIFIER_DEPLOYMENT_INPUT,
  }),
  call_policy: Object.freeze({
    address: resolvePolicyModule("call"),
    runtimeCodeHash: "0x99fc4b02bdbb9a5133728a2bfffb458bf8530b1b068d6d4334f69dcb454ace78",
    deploymentInput: CALL_POLICY_DEPLOYMENT_INPUT,
  }),
  operation_limit_policy: Object.freeze({
    address: resolvePolicyModule("operation-limit"),
    runtimeCodeHash: "0xb4fffdb494637e8e5bfc15d6500202c252392b498e518668f896dc6da0221183",
    deploymentInput: OPERATION_LIMIT_POLICY_DEPLOYMENT_INPUT,
  }),
  ecdsa_signer: Object.freeze({
    address: resolvePinnedSigner("ecdsa"),
    runtimeCodeHash: "0x510a0a1ab8b3f256a5c90b5fff51a9fd98656bd1c8a29fbd7857faa70c400ccd",
    deploymentInput: ECDSA_SIGNER_DEPLOYMENT_INPUT,
  }),
});

const MODULE_ORDER = Object.freeze(Object.keys(RUNTIME_MODULES) as KernelRuntimeModule[]);

function capturedModule(value: unknown): KernelRuntimeModule {
  if (typeof value !== "string" || !Object.hasOwn(RUNTIME_MODULES, value))
    return inputInvalid("Kernel runtime module is unsupported");
  return value as KernelRuntimeModule;
}

/**
 * Observes whether one address carries exactly one expected runtime code hash.
 * Absence is proven only by an empty `code` read that agrees with an absent
 * hash; any failed, malformed or contradictory read is `unreadable`.
 */
export async function observeRuntimeModule(
  read: KernelReads["read"],
  chainId: number,
  address: `0x${string}`,
  expected: `0x${string}`,
): Promise<KernelRuntimeModuleStatus> {
  let hash: unknown;
  let code: unknown;
  try {
    hash = await read({ type: "runtime_code_hash", chainId, address });
    if (hash === expected) return "present";
    code = await read({ type: "code", chainId, address });
  } catch {
    return "unreadable";
  }
  if (!isBytes(code)) return "unreadable";
  if (code === "0x") return hash === undefined ? "missing" : "unreadable";
  const observed = keccak256(code);
  return observed !== expected && hash === observed ? "mismatch" : "unreadable";
}

/** Reports every OAAth runtime module's presence on one chain. */
export async function kernelRuntimeReadiness(
  value: KernelRuntimeReadinessInput,
): Promise<Readonly<KernelRuntimeReadiness>> {
  const record = exactInput(value, ["chainId", "reads"], "Kernel runtime readiness", new WeakSet());
  const { chainId } = kernelV4Deployment(record.chainId);
  const read = inputCapability<KernelReads["read"]>(
    exactInput(record.reads, ["read"], "Kernel runtime readiness reads", new WeakSet()).read,
    "Kernel runtime readiness reads",
  );
  let boundChain: unknown;
  try {
    boundChain = await read({ type: "chain_id", chainId });
  } catch {
    boundChain = undefined;
  }
  const modules: Readonly<KernelRuntimeModuleReadiness>[] = [];
  for (const module of MODULE_ORDER) {
    const row = RUNTIME_MODULES[module];
    const status =
      boundChain === chainId
        ? await observeRuntimeModule(read, chainId, row.address, row.runtimeCodeHash)
        : "unreadable";
    modules.push(Object.freeze({ module, address: row.address, status, deployment: "oaath" }));
  }
  return Object.freeze({ chainId, modules: Object.freeze(modules) });
}

/** The exact CREATE2 deployer transaction that deploys one runtime module. */
export function prepareRuntimeModuleDeployment(
  value: PrepareRuntimeModuleDeploymentInput,
): Readonly<KernelRuntimeModuleDeployment> {
  const record = exactInput(
    value,
    ["chainId", "module"],
    "Kernel runtime module deployment",
    new WeakSet(),
  );
  const deployment = kernelV4Deployment(record.chainId);
  const module = capturedModule(record.module);
  const row = RUNTIME_MODULES[module];
  return Object.freeze({
    module,
    address: row.address,
    to: deployment.create2Deployer,
    data: row.deploymentInput,
    value: 0n,
    expectedRuntimeCodeHash: row.runtimeCodeHash,
  });
}
