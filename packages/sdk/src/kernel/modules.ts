/**
 * Pinned ERC-7579 module deployments for Kernel v4. Contract addresses live here
 * and in kernel-v4.ts only, never duplicated across key, operator, or hook files.
 * An unbound axis fails closed; never add an address that has not been reviewed
 * and proven.
 *
 * Every address here is chain-independent. These modules are deployed through the
 * CREATE2 deployer at KERNEL_V4_CREATE2_DEPLOYER with a zero salt, so one address
 * holds on every supported chain and no module is keyed per chain. Per-chain facts
 * stay where the evidence genuinely differs: the deployment profile's runtime code
 * hashes in kernel-v4.ts (Kernel caches block.chainid in its immutables, so one
 * address carries different runtime code per chain) and the code-presence reads
 * bindKernelV4Account performs on the action chain.
 *
 * @author taek <leekt216@gmail.com>
 */
import { type KernelV4Deployment, kernelV4Deployment } from "../kernel-v4.js";
import { inputInvalid, runtimeFail } from "./internal.js";
import type { KernelKeyKind, KernelPolicyProfile } from "./types.js";

/**
 * Validator modules (moduleType 1) bound per key kind. Kernel v4 ships no reviewed
 * raw P-256 or WebAuthn validator deployment yet, so both kinds resolve to absent
 * and every composition using them fails closed. ECDSA carries no entry by design:
 * kernel/key/ecdsa.ts binds the caller's validator module and bindKernelV4Account
 * proves it has code before any account address depends on it.
 */
const PINNED_VALIDATORS: Readonly<Partial<Record<KernelKeyKind, `0x${string}`>>> = Object.freeze(
  {},
);

/**
 * Permission signer modules (moduleType 6) bound per key kind. Both are reviewed
 * modules from https://github.com/zerodevapp/kernel-7579-plugins at commit
 * 332deed6eeef3d6279cde50aa1d51eff53728bd4, compiled with solc
 * 0.8.30+commit.73712a01 (via-IR, optimizer 20000 runs, EVM prague) and deployed
 * through KERNEL_V4_CREATE2_DEPLOYER with a zero salt, which fixes each address on
 * every chain. test/fixtures/kernel-v4-v0.7-deployments.json carries the exact
 * deployment input, and the local Kernel composition proof deploys it and shows
 * the code landing on the address pinned here.
 *
 * - ecdsa: src/signers/ECDSASigner.sol — onInstall takes the 20-byte signer
 *   address, exactly the public material kernel/key/ecdsa.ts publishes.
 * - webauthn: src/signers/WebAuthnSigner.sol — onInstall decodes
 *   (uint256 pubKeyX, uint256 pubKeyY, bytes32), exactly the public material
 *   kernel/key/webauthn.ts publishes.
 *
 * Raw P-256 carries no entry: the reviewed plugin set ships only the WebAuthn
 * assertion signer, so a raw P-256 permission signer fails closed.
 */
const PINNED_SIGNERS: Readonly<Partial<Record<KernelKeyKind, `0x${string}`>>> = Object.freeze({
  ecdsa: "0xd4c7dec43e67ffe3dcca0aeb71556123d3194e1d",
  webauthn: "0x8b2df925aa16071fcdf0053768420e242935ac65",
});

/**
 * ZeroDev's reviewed CallPolicy (moduleType 5), which bounds every permitted
 * (callType, target, selector) triple and the native value each may move.
 * Package `zerodev-kernel-call-policy` 0.0.4, source mirrored at
 * https://github.com/cartesi/erc-4337-devnet
 * (zerodev/kernel-call-policy/0.0.4/src/CallPolicy.sol) together with its exact
 * Kernel v3 dependency sources and build profile (solc 0.8.24+commit.e11b9ed9,
 * via-IR, optimizer 200 runs, EVM paris, bytecode hash and CBOR metadata
 * disabled). Recompiling that source with that profile reproduces the package's
 * own cannon `expected` address bit for bit, so this address is ZeroDev's, not
 * ours. It is deployed through KERNEL_V4_CREATE2_DEPLOYER with a zero salt, so
 * one address holds on every chain.
 *
 * Kernel v4 and v3 declare the identical IPolicy: checkUserOpPolicy(bytes32 id,
 * PackedUserOperation) and PolicyBase.onInstall(bytes32 id ‖ data). The module
 * decodes the outer execute(bytes32,bytes) calldata, which is why permission
 * validations must not wrap their calldata in executeUserOp.
 */
const CALL_POLICY = "0x9a52283276a0ec8740df50bf01b28a80d880eaf2" as const;

/**
 * Policy modules bound per policy axis. CallPolicy enforces the call and value
 * axes together, in one module, from one configuration. No reviewed Kernel v4
 * expiry or per-chain operation-limit policy module exists, so those two axes
 * resolve to absent and any session requesting them fails closed instead of
 * being narrowed to the axes that do materialize.
 */
const PINNED_POLICIES: Readonly<Partial<Record<KernelPolicyProfile["kind"], `0x${string}`>>> =
  Object.freeze({
    call: CALL_POLICY,
    value: CALL_POLICY,
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
export function pinnedValidatorModule(kind: KernelKeyKind): `0x${string}` | null {
  return PINNED_VALIDATORS[kind] ?? null;
}

/** The reviewed permission signer module bound to one key kind, or null when none is. */
export function pinnedSignerModule(kind: KernelKeyKind): `0x${string}` | null {
  return PINNED_SIGNERS[kind] ?? null;
}

/** The reviewed policy module bound to one policy axis, or null when none is. */
export function pinnedPolicyModule(kind: KernelPolicyProfile["kind"]): `0x${string}` | null {
  return PINNED_POLICIES[kind] ?? null;
}

/** Resolves the reviewed validator module for one key kind, or fails closed. */
export function resolvePinnedValidator(kind: KernelKeyKind): `0x${string}` {
  return (
    pinnedValidatorModule(kind) ??
    runtimeFail(
      "kernel_runtime_validator_unavailable",
      `Kernel v4 has no reviewed ${kind} validator module deployment`,
    )
  );
}

/** Resolves the reviewed permission signer module for one key kind, or fails closed. */
export function resolvePinnedSigner(kind: KernelKeyKind): `0x${string}` {
  return (
    pinnedSignerModule(kind) ??
    runtimeFail(
      "kernel_runtime_signer_unavailable",
      `Kernel v4 has no reviewed ${kind} permission signer module deployment`,
    )
  );
}

/** Resolves the reviewed policy module enforcing one policy axis, or fails closed. */
export function resolvePolicyModule(kind: KernelPolicyProfile["kind"]): `0x${string}` {
  return (
    pinnedPolicyModule(kind) ??
    runtimeFail(
      "kernel_runtime_policy_unavailable",
      `Kernel v4 has no reviewed ${kind} policy module deployment`,
    )
  );
}
